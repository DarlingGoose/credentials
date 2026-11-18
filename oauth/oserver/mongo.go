package oserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var _ OServer = &MongoServer{}

// MongoServer implements the OAuth2 OServer interface backed by MongoDB
type MongoServer struct {
	db          *mongo.Database
	clientsColl *mongo.Collection
	tokensColl  *mongo.Collection
	jwkColl     *mongo.Collection
	imagesColl  *mongo.Collection
}

// NewMongoServer creates a new MongoServer. Expects a connected mongo.Database.
func NewMongoServer(db *mongo.Database) *MongoServer {
	return &MongoServer{
		db:          db,
		clientsColl: db.Collection("oauth_clients"),
		tokensColl:  db.Collection("oauth_tokens"),
		jwkColl:     db.Collection("oauth_jwks"),
		imagesColl:  db.Collection("oauth_client_images"),
	}
}
func ss(i interface{}) string {
	switch v := i.(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	default:
		slog.Error("skipping type")
		return ""
	}
}

// helper to produce a URL-safe base64 secret of n bytes
func generateSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// RegisterClient inserts a new OAuth client into the store.
func (s *MongoServer) RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"client_credentials"}
	}
	if client.TokenEndpointAuth == "" {
		client.TokenEndpointAuth = "client_secret_post"
	}
	if len(client.RedirectURIs) == 0 {
		return nil, fmt.Errorf("no redirect_uris provided")
	}
	if client.Name == "" {
		return nil, fmt.Errorf("no name provided")
	}
	clientID := uuid.New().String()

	// 2) generate a random 32-byte secret (URL-safe base64)
	secret, err := generateSecret(32)
	if err != nil {
		return nil, err
	}

	// 3) assign back onto your model
	client.ClientID = clientID
	client.ClientSecret = secret

	// 4) persist to Mongo
	clientDoc := bson.M{
		"client_id":                  client.ClientID,
		"account_id":                 client.AccountID,
		"client_secret":              client.ClientSecret,
		"name":                       client.Name,
		"image_url":                  client.ImageURL,
		"redirect_uris":              client.RedirectURIs,
		"scopes":                     client.Scopes,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuth,
	}

	if _, err := s.clientsColl.InsertOne(ctx, clientDoc); err != nil {
		return nil, err
	}

	return client, nil
}

// GetClient retrieves a client by ID.
func (s *MongoServer) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var doc bson.M
	err := s.clientsColl.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	client := &OAuthClient{
		ClientID:          ss(doc["client_id"]),
		ClientSecret:      ss(doc["client_secret"]),
		AccountID:         ss(doc["account_id"]),
		Name:              ss(doc["name"]),
		ImageURL:          ss(doc["image_url"]),
		RedirectURIs:      castStringSlice(doc["redirect_uris"]),
		Scopes:            castStringSlice(doc["scopes"]),
		GrantTypes:        castStringSlice(doc["grant_types"]),
		ResponseTypes:     castStringSlice(doc["response_types"]),
		TokenEndpointAuth: ss(doc["token_endpoint_auth_method"]),
	}
	return client, nil
}

// ListClients returns all clients for a given accountID (if stored) or all clients.
func (s *MongoServer) ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error) {
	filter := bson.M{}
	// if you store accountID in client docs:
	if accountID != "" {
		filter["account_id"] = accountID
	}
	cur, err := s.clientsColl.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cur.Close(ctx)
	}()
	var list []*OAuthClient
	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		if ss(doc["client_id"]) == "" {
			slog.Error("skipping client, no client id")
			continue
		}
		if ss(doc["name"]) == "" {
			slog.Error("skipping client, no name")
			continue
		}
		if ss(doc["account_id"]) != "" && ss(doc["account_id"]) != accountID {
			continue
		}
		list = append(list, &OAuthClient{
			ClientID:      ss(doc["client_id"]),
			Name:          ss(doc["name"]),
			RedirectURIs:  castStringSlice(doc["redirect_uris"]),
			Scopes:        castStringSlice(doc["scopes"]),
			GrantTypes:    castStringSlice(doc["grant_types"]),
			ResponseTypes: castStringSlice(doc["response_types"]),
		})
	}
	return list, nil
}

// UpdateClient updates mutable fields on an existing client.
func (s *MongoServer) UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	update := bson.M{"$set": bson.M{
		"name":                       client.Name,
		"image_url":                  client.ImageURL,
		"redirect_uris":              client.RedirectURIs,
		"scopes":                     client.Scopes,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuth,
	}}
	_, err := s.clientsColl.UpdateOne(ctx, bson.M{"client_id": client.ClientID}, update)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// DeleteClient removes a client by ID.
func (s *MongoServer) DeleteClient(ctx context.Context, clientID string) error {
	res, err := s.clientsColl.DeleteOne(ctx, bson.M{"client_id": clientID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return errors.New("client not found")
	}
	return nil
}

// Authorize issues an authorization code and stores it in tokens collection.

func (s *MongoServer) Authorize(ctx context.Context, principal AuthorizationPrincipal, req AuthRequest) (*AuthResponse, error) {
	if err := validateAuthorizationPrincipal(principal); err != nil {
		return nil, err
	}
	if _, err := ValidateAuthorizationRequest(ctx, s, req); err != nil {
		return nil, err
	}
	code, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	rec := bson.M{
		"code":                  hashOpaqueToken(code),
		"client_id":             req.ClientID,
		"redirect_uri":          req.RedirectURI,
		"scope":                 req.Scope,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"grant_type":            GrantTypeAuthorizationCode,
		"created_at":            time.Now().Unix(),
		"user_id":               principal.UserID,
		"account_id":            principal.AccountID,
	}
	_, err = s.tokensColl.InsertOne(ctx, rec)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{Code: code, State: req.State}, nil
}

// TokenRequest and TokenResponse mirror OAuth2 spec
// ... [other types omitted for brevity] ...

// Token handles all grant types: authorization_code, refresh_token, client_credentials
func (s *MongoServer) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	now := time.Now()
	switch req.GrantType {
	case string(GrantTypeAuthorizationCode):
		if err := validateTokenClient(ctx, s, req); err != nil {
			return nil, err
		}
		codeHash := hashOpaqueToken(req.Code)
		var rec struct {
			Code                string `bson:"code"`
			ClientID            string `bson:"client_id"`
			RedirectURI         string `bson:"redirect_uri"`
			Scope               string `bson:"scope"`
			CodeChallenge       string `bson:"code_challenge"`
			CodeChallengeMethod string `bson:"code_challenge_method"`
			CreatedAt           int64  `bson:"created_at"`
		}
		err := s.tokensColl.FindOne(ctx, bson.M{"code": codeHash}).Decode(&rec)
		if err != nil {
			return nil, errors.New("invalid authorization code")
		}
		if rec.RedirectURI != req.RedirectURI {
			return nil, errors.New("redirect_uri mismatch")
		}
		if rec.ClientID != req.ClientID {
			return nil, errors.New("authorization code client mismatch")
		}
		if rec.CreatedAt <= 0 || now.After(time.Unix(rec.CreatedAt, 0).Add(authorizationCodeTTL)) {
			return nil, errors.New("authorization code expired")
		}
		if rec.CodeChallengeMethod != "S256" || rec.CodeChallenge == "" || !ValidateCodeChallenge(req.CodeVerifier, rec.CodeChallenge) {
			return nil, errors.New("invalid code_verifier")
		}
		accessToken, err := newOpaqueToken()
		if err != nil {
			return nil, err
		}
		refreshToken, err := newOpaqueToken()
		if err != nil {
			return nil, err
		}
		expiresAt := now.Add(time.Hour).Unix()
		filter := bson.M{
			"code":         codeHash,
			"client_id":    req.ClientID,
			"redirect_uri": req.RedirectURI,
			"created_at":   bson.M{"$gte": now.Add(-authorizationCodeTTL).Unix()},
		}
		update := bson.M{
			"$unset": bson.M{"code": ""},
			"$set": bson.M{
				"access_token":       hashOpaqueToken(accessToken),
				"refresh_token":      hashOpaqueToken(refreshToken),
				"refresh_history":    bson.A{},
				"refresh_generation": int64(0),
				"refresh_revoked_at": int64(0),
				"expires_at":         expiresAt,
			},
		}
		result, err := s.tokensColl.UpdateOne(ctx, filter, update)
		if err != nil {
			return nil, err
		}
		if result.MatchedCount != 1 {
			return nil, errors.New("authorization code already consumed")
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), RefreshToken: refreshToken, Scope: rec.Scope}, nil

	case string(GrantTypeRefreshToken):
		if err := validateTokenClient(ctx, s, req); err != nil {
			return nil, err
		}
		refreshHash := hashOpaqueToken(req.RefreshToken)
		accessToken, err := newOpaqueToken()
		if err != nil {
			return nil, err
		}
		refreshToken, err := newOpaqueToken()
		if err != nil {
			return nil, err
		}
		expiresAt := now.Add(time.Hour).Unix()
		var rec struct {
			Scope string `bson:"scope"`
		}
		err = s.tokensColl.FindOneAndUpdate(ctx,
			bson.M{
				"refresh_token":      refreshHash,
				"client_id":          req.ClientID,
				"refresh_revoked_at": int64(0),
			},
			bson.M{
				"$push": bson.M{"refresh_history": refreshHash},
				"$inc":  bson.M{"refresh_generation": int64(1)},
				"$set": bson.M{
					"access_token":  hashOpaqueToken(accessToken),
					"refresh_token": hashOpaqueToken(refreshToken),
					"expires_at":    expiresAt,
				},
			},
			options.FindOneAndUpdate().SetReturnDocument(options.After),
		).Decode(&rec)
		if errors.Is(err, mongo.ErrNoDocuments) {
			result, revokeErr := s.tokensColl.UpdateOne(ctx,
				bson.M{"client_id": req.ClientID, "refresh_history": refreshHash},
				bson.M{
					"$set":   bson.M{"refresh_revoked_at": now.Unix(), "expires_at": int64(0)},
					"$unset": bson.M{"access_token": "", "refresh_token": ""},
				})
			if revokeErr != nil {
				return nil, revokeErr
			}
			if result.MatchedCount == 1 {
				return nil, errors.New("refresh token reuse detected")
			}
			return nil, errors.New("invalid refresh token")
		}
		if err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), RefreshToken: refreshToken, Scope: rec.Scope}, nil

	case "client_credentials":
		// authenticate client
		var cli struct {
			ClientSecret string   `bson:"client_secret"`
			Scopes       []string `bson:"scopes"`
			GrantTypes   []string `bson:"grant_types"`
		}
		err := s.clientsColl.FindOne(ctx, bson.M{"client_id": req.ClientID}).Decode(&cli)
		if err != nil {
			return nil, errors.New("invalid client credentials")
		}
		if cli.ClientSecret != req.ClientSecret {
			return nil, errors.New("invalid client credentials")
		}
		// ensure grant type allowed
		allowed := false
		for _, gt := range cli.GrantTypes {
			if gt == "client_credentials" {
				allowed = true
			}
		}
		if !allowed {
			return nil, errors.New("grant_type not allowed")
		}
		accessToken, err := newOpaqueToken()
		if err != nil {
			return nil, err
		}
		expiresAt := now.Add(time.Hour).Unix()
		scopeStr := strings.Join(cli.Scopes, " ")
		// insert token record
		_, err = s.tokensColl.InsertOne(ctx, bson.M{
			"access_token": hashOpaqueToken(accessToken),
			"client_id":    req.ClientID,
			"scope":        scopeStr,
			"grant_type":   "client_credentials",
			"expires_at":   expiresAt,
		})
		if err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), Scope: scopeStr}, nil

	default:
		return nil, errors.New("unsupported grant_type")
	}
}

// Revoke invalidates a token (remove or mark revoked)
func (s *MongoServer) Revoke(ctx context.Context, req RevocationRequest) error {
	tokenHash := hashOpaqueToken(req.Token)
	_, err := s.tokensColl.DeleteOne(ctx, bson.M{"$or": []bson.M{{"access_token": tokenHash}, {"refresh_token": tokenHash}}})
	return err
}

// Introspect checks active state of a token
func (s *MongoServer) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	var doc bson.M
	err := s.tokensColl.FindOne(ctx, bson.M{"access_token": hashOpaqueToken(req.Token)}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &IntrospectResponse{Active: false}, nil
		}
		return nil, err
	}
	expires := doc["expires_at"].(int64)
	active := time.Now().Unix() < expires
	return &IntrospectResponse{
		Active:    active,
		ClientID:  ss(doc["client_id"]),
		Scope:     ss(doc["scope"]),
		Exp:       expires,
		UserID:    ss(doc["user_id"]),
		AccountID: ss(doc["account_id"]),
	}, nil
}

type JWKs struct {
	Key json.RawMessage `json:"key" bson:"key"`
}

// JWKs returns stored JWK set
// JWKs returns stored JWK set
func (s *MongoServer) JWKs(ctx context.Context) (*JWKSet, error) {
	cur, err := s.jwkColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	var keys []json.RawMessage
	for cur.Next(ctx) {
		var doc JWKs
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		keys = append(keys, doc.Key)
	}
	return &JWKSet{Keys: keys}, nil
}

// SetClientImage uploads or updates an image for a given client.
func (s *MongoServer) SetClientImage(r *http.Request, clientID string) error {
	ctx := r.Context()
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return err
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	// upsert image document
	_, err = s.imagesColl.UpdateOne(ctx, bson.M{"client_id": clientID}, bson.M{
		"$set": bson.M{
			"data":         data,
			"content_type": header.Header.Get("Content-Type"),
			"updated_at":   time.Now(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// SendClientImage streams the stored image to the HTTP response.
func (s *MongoServer) SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error {
	ctx := r.Context()
	var doc struct {
		Data        []byte `bson:"data"`
		ContentType string `bson:"content_type"`
	}
	err := s.imagesColl.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.NotFound(w, r)
			return nil
		}
		return err
	}
	// add caching headers
	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, err = w.Write(doc.Data)
	return err
}

func (s *MongoServer) HasAccess(r *http.Request, resource string, hasRbacAccess func(resource string, userId, accountId string, scopes ...string) bool) (bool, error) {
	ctx := r.Context()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		// no token: empty user and scopes
		return hasRbacAccess(resource, "", ""), nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	var doc bson.M
	err := s.tokensColl.FindOne(ctx, bson.M{"access_token": hashOpaqueToken(token)}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}
	// check expiration
	expires, ok := doc["expires_at"].(int64)
	if !ok || time.Now().Unix() >= expires {
		return false, nil
	}
	// extract user and scopes
	userId, _ := doc["user_id"].(string)
	accountId, _ := doc["account_id"].(string)
	scopeStr, _ := doc["scope"].(string)
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}
	allowed := hasRbacAccess(resource, userId, accountId, scopes...)
	return allowed, nil
}

// helpers
func castStringSlice(v interface{}) []string {
	if arr, ok := v.(primitive.A); ok {
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

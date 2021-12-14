package osinredis

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/RangelReale/osin"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func init() {
	gob.Register(map[string]interface{}{})
	gob.Register(&osin.DefaultClient{})
	gob.Register(osin.AuthorizeData{})
	gob.Register(osin.AccessData{})
}

// Storage implements "github.com/RangelReale/osin".Storage
type Storage struct {
	pool      *redis.Client
	keyPrefix string
}

// New initializes and returns a new Storage
func New(pool *redis.Client, keyPrefix string) *Storage {
	return &Storage{
		pool:      pool,
		keyPrefix: keyPrefix,
	}
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {}

// CreateClient inserts a new client
func (s *Storage) CreateClient(client osin.Client) error {
	ctx := context.Background()

	payload, err := encode(client)
	if err != nil {
		return errors.Wrap(err, "failed to encode client")
	}

	return s.pool.Set(ctx, s.makeKey("client", client.GetId()), payload, 0).Err()
}

// GetClient gets a client by ID
func (s *Storage) GetClient(id string) (osin.Client, error) {
	ctx := context.Background()

	rawClientGob, err := s.pool.Get(ctx, s.makeKey("client", id)).Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "unable to GET client")
	}
	if len(rawClientGob) == 0 {
		return nil, nil
	}

	var client osin.DefaultClient
	err = decode(rawClientGob, &client)
	return &client, errors.Wrap(err, "failed to decode client gob")
}

// UpdateClient updates a client
func (s *Storage) UpdateClient(client osin.Client) error {
	return errors.Wrap(s.CreateClient(client), "failed to update client")
}

// DeleteClient deletes given client
func (s *Storage) DeleteClient(client osin.Client) error {
	ctx := context.Background()
	return s.pool.Del(ctx, s.makeKey("client", client.GetId())).Err()
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) (err error) {
	ctx := context.Background()

	payload, err := encode(data)
	if err != nil {
		return errors.Wrap(err, "failed to encode data")
	}

	return s.pool.SetEX(ctx, s.makeKey("auth", data.Code), string(payload), time.Duration(data.ExpiresIn)*time.Second).Err()
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	ctx := context.Background()

	rawClientGob, err := s.pool.Get(ctx, s.makeKey("auth", code)).Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "unable to GET auth")
	}
	if len(rawClientGob) == 0 {
		return nil, nil
	}

	var auth osin.AuthorizeData
	err = decode(rawClientGob, &auth)
	return &auth, errors.Wrap(err, "failed to decode auth")
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) (err error) {
	ctx := context.Background()

	return s.pool.Del(ctx, s.makeKey("auth", code)).Err()
}

// SaveAccess creates AccessData.
func (s *Storage) SaveAccess(data *osin.AccessData) (err error) {
	ctx := context.Background()

	payload, err := encode(data)
	if err != nil {
		return errors.Wrap(err, "failed to encode access")
	}

	accessID := uuid.NewV4().String()

	if err := s.pool.SetEX(ctx, s.makeKey("access", accessID), string(payload), time.Duration(data.ExpiresIn)).Err(); err != nil {
		return errors.Wrap(err, "failed to save access")
	}

	if err := s.pool.SetEX(ctx, s.makeKey("access_token", data.AccessToken), accessID, time.Duration(data.ExpiresIn)).Err(); err != nil {
		return errors.Wrap(err, "failed to register access token")
	}

	err = s.pool.SetEX(ctx, s.makeKey("refresh_token", data.AccessToken), accessID, time.Duration(data.ExpiresIn)).Err()
	return errors.Wrap(err, "failed to register refresh token")
}

// LoadAccess gets access data with given access token
func (s *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	return s.loadAccessByKey(s.makeKey("access_token", token))
}

// RemoveAccess deletes AccessData with given access token
func (s *Storage) RemoveAccess(token string) error {
	return s.removeAccessByKey(s.makeKey("access_token", token))
}

// LoadRefresh gets access data with given refresh token
func (s *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	return s.loadAccessByKey(s.makeKey("refresh_token", token))
}

// RemoveRefresh deletes AccessData with given refresh token
func (s *Storage) RemoveRefresh(token string) error {
	return s.removeAccessByKey(s.makeKey("refresh_token", token))
}

func (s *Storage) removeAccessByKey(key string) error {
	ctx := context.Background()

	accessID, err := s.pool.Get(ctx, key).Result()
	if err != nil {
		return errors.Wrap(err, "failed to get access")
	}

	access, err := s.loadAccessByKey(key)
	if err != nil {
		return errors.Wrap(err, "unable to load access for removal")
	}

	if access == nil {
		return nil
	}

	accessKey := s.makeKey("access", accessID)

	if err := s.pool.Del(ctx, accessKey).Err(); err != nil {
		return errors.Wrap(err, "failed to delete access")
	}

	accessTokenKey := s.makeKey("access_token", access.AccessToken)
	if err := s.pool.Del(ctx, accessTokenKey).Err(); err != nil {
		return errors.Wrap(err, "failed to deregister access_token")
	}

	refreshTokenKey := s.makeKey("refresh_token", access.RefreshToken)
	err = s.pool.Del(ctx, refreshTokenKey).Err()
	return errors.Wrap(err, "failed to deregister refresh_token")
}

func (s *Storage) loadAccessByKey(key string) (*osin.AccessData, error) {
	ctx := context.Background()

	accessID, err := s.pool.Get(ctx, key).Result()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access ID")
	}

	accessIDKey := s.makeKey("access", accessID)
	accessGob, err := s.pool.Get(ctx, accessIDKey).Bytes()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access gob")
	}

	var access osin.AccessData
	if err := decode(accessGob, &access); err != nil {
		return nil, errors.Wrap(err, "failed to decode access gob")
	}

	ttl, err := s.pool.TTL(ctx, accessIDKey).Result()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access TTL")
	}

	access.ExpiresIn = int32(ttl)

	access.Client, err = s.GetClient(access.Client.GetId())
	if err != nil {
		return nil, errors.Wrap(err, "unable to get client for access")
	}

	if access.AuthorizeData != nil && access.AuthorizeData.Client != nil {
		access.AuthorizeData.Client, err = s.GetClient(access.AuthorizeData.Client.GetId())
		if err != nil {
			return nil, errors.Wrap(err, "unable to get client for access authorize data")
		}
	}

	return &access, nil
}

func (s *Storage) makeKey(namespace, id string) string {
	return fmt.Sprintf("%s:%s:%s", s.keyPrefix, namespace, id)
}

func encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, errors.Wrap(err, "unable to encode")
	}
	return buf.Bytes(), nil
}

func decode(data []byte, v interface{}) error {
	err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(v)
	return errors.Wrap(err, "unable to decode")
}

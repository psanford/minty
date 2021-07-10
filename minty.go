package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/inconshreveable/log15"
	"github.com/psanford/lambdahttp/lambdahttpv2"
	"github.com/psanford/logmiddleware"
	"github.com/psanford/minty/config"
	"github.com/psanford/minty/messages"
)

var (
	addr    = flag.String("listen-addr", "127.0.0.1:1234", "Host/Port to listen on")
	cliMode = flag.String("mode", "lambda", "execution mode: http|lambda")
)

func main() {
	flag.Parse()

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)
	lgr := log15.New()

	kv := newKV()

	accessKeyID := kv.mustGet("accessKeyId")
	secretAccessKey := kv.mustGet("secretAccessKey")

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
	})
	if err != nil {
		panic(err)
	}

	stsService := sts.New(sess)

	conf := config.LoadCloudConfig(lgr)
	if conf == nil {
		panic("Failed to load config")
	}

	s := &server{
		sts:        stsService,
		challenges: make(map[string]*pendingChallenge),
		keyToUser:  make(map[string]*userKey),
	}

	for _, user := range conf.Users {
		for _, pubPem := range user.EndorsementKeys {
			pubPem = strings.TrimSpace(pubPem)
			key, err := parseKey(pubPem)
			if err != nil {
				lgr.Error("parse_key_err", "key", pubPem, "user", user.ID, "err", err)
				os.Exit(1)
			}

			canonicalPem, err := keyToPem(key)
			if err != nil {
				lgr.Error("key_to_pem_err", "key", pubPem, "user", user.ID, "err", err)
				os.Exit(1)
			}

			user := user
			s.keyToUser[string(canonicalPem)] = &userKey{
				user: &user,
				ek:   key,
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/minty/request_challenge", s.challengeHandler)
	mux.HandleFunc("/minty/prove", s.proofHandler)

	h := logmiddleware.New(mux)

	switch *cliMode {
	case "http":
		fmt.Printf("Listening on %s\n", *addr)
		panic(http.ListenAndServe(*addr, h))
	default:
		lambda.Start(lambdahttpv2.NewLambdaHandler(h))
	}
}

type server struct {
	keyToUser map[string]*userKey

	sts *sts.STS

	mu         sync.Mutex
	challenges map[string]*pendingChallenge
}

type userKey struct {
	user *config.User
	ek   crypto.PublicKey
}

type pendingChallenge struct {
	ek     crypto.PublicKey
	ak     crypto.PublicKey
	akHash crypto.Hash
	secret []byte
}

func (s *server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	var req messages.RequestChallenge
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		lgr.Error("decode_json_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	params := req.AttestationParameters
	ak := attest.AttestationParameters{
		Public:                  params.Public,
		UseTCSDActivationFormat: params.UseTCSDActivationFormat,
		CreateData:              params.CreateData,
		CreateAttestation:       params.CreateAttestation,
		CreateSignature:         params.CreateSignature,
	}

	ek, err := parseKey(req.EndorsementKeyPem)
	if err != nil {
		lgr.Error("parse_ek_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	akActivationParams := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion(req.TPMVersion),
		EK:         ek,
		AK:         ak,
	}

	secret, encryptedCredentials, err := akActivationParams.Generate()
	if err != nil {
		lgr.Error("generate_challenge_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tpmKey, err := tpm2.DecodePublic(ak.Public)
	if err != nil {
		lgr.Error("parse_tpm2_ak_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	akPubKey, err := tpmKey.Key()
	if err != nil {
		lgr.Error("get_ak_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	hash, err := tpmKey.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		lgr.Error("get_ak_hash_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()

	challengeIDBytes := make([]byte, 20)
	rand.Read(challengeIDBytes)

	challengeID := hex.EncodeToString(challengeIDBytes)
	s.challenges[challengeID] = &pendingChallenge{
		ek:     ek,
		ak:     akPubKey,
		akHash: hash,
		secret: secret,
	}
	s.mu.Unlock()

	resp := messages.ChallengeResponse{
		ChallengeID: challengeID,
		Credential:  encryptedCredentials.Credential,
		Secret:      encryptedCredentials.Secret,
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *server) proofHandler(w http.ResponseWriter, r *http.Request) {
	lgr := logmiddleware.LgrFromContext(r.Context())
	var proof messages.ChallengeProof
	err := json.NewDecoder(r.Body).Decode(&proof)
	if err != nil {
		lgr.Error("decode_json_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	pending := s.challenges[proof.ChallengeID]
	delete(s.challenges, proof.ChallengeID)
	s.mu.Unlock()

	if pending == nil {
		lgr.Error("no_key_found_for_secret")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if subtle.ConstantTimeCompare(proof.Secret, pending.secret) != 1 {
		lgr.Error("bad_secret")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	canonicalPem, err := keyToPem(pending.ek)
	if err != nil {
		lgr.Error("key_to_pem_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user := s.keyToUser[canonicalPem]
	if user == nil {
		lgr.Error("user_not_found")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	params := proof.CertificationParameters
	certParams := attest.CertificationParameters{
		Public:            params.Public,
		CreateData:        params.CreateData,
		CreateAttestation: params.CreateAttestation,
		CreateSignature:   params.CreateSignature,
	}

	err = certParams.Verify(attest.VerifyOpts{
		Public: pending.ak,
		Hash:   pending.akHash,
	})
	if err != nil {
		lgr.Error("verify_app_key_err", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var allowed bool
	for _, roleARN := range user.user.AuthorizedRoles {
		if roleARN == proof.RoleARN {
			allowed = true
			break
		}
	}

	if !allowed {
		lgr.Error("requested_role_not_authorized", "role", proof.RoleARN)
		w.WriteHeader(400)
		fmt.Fprintf(w, "requested_role_not_authorized\n")
		return
	}

	timeoutSeconds := 60 * 60

	sessionName := fmt.Sprintf("minty-%s", user.user.ID)

	out, err := s.sts.AssumeRole(&sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(timeoutSeconds)),
		RoleArn:         aws.String(proof.RoleARN),
		RoleSessionName: aws.String(sessionName),
	})

	if err != nil {
		lgr.Error("assume_role_err", "err", err)
		w.WriteHeader(400)
		fmt.Fprintf(w, "aws assumerole error: %s", err)
		return
	}

	resp := messages.Credentials{
		Credentials: out.Credentials,
		Region:      "us-east-1",
	}
	json.NewEncoder(w).Encode(&resp)
}

func parseKey(keyPem string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return nil, errors.New("decode pem fail")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key err: %w", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unsupported public key type")
	}
}

func keyToPem(key crypto.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal pkix err: %w", err)
	}

	canonicalPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	})

	return string(canonicalPem), nil
}

func (kv *kv) mustGet(key string) string {
	v, err := kv.get(key)
	if err != nil {
		panic(err)
	}
	return v
}

func (kv *kv) get(key string) (string, error) {
	ssmPath := os.Getenv("SSM_PATH")
	if ssmPath == "" {
		return "", errors.New("SSM_PATH not set")
	}
	p := path.Join(ssmPath, key)

	req := ssm.GetParameterInput{
		Name:           &p,
		WithDecryption: aws.Bool(true),
	}

	resp, err := kv.client.GetParameter(&req)
	if err != nil {
		return "", fmt.Errorf("read key %s err: %w", key, err)
	}
	val := resp.Parameter.Value
	if val == nil {
		return "", errors.New("value is nil")
	}
	return *val, nil
}

func newKV() *kv {
	sess := session.Must(session.NewSession())
	ssmClient := ssm.New(sess)

	return &kv{
		client: ssmClient,
	}
}

type kv struct {
	client *ssm.SSM
}

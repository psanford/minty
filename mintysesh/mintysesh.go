package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/go-attestation/attest"
	"github.com/inconshreveable/log15"
	"github.com/psanford/minty/messages"
)

var (
	printEK   = flag.Bool("print-keys", false, "Print TPM EK keys and exit")
	serverURL = flag.String("url", "localhost:1234", "Server url")
	roleARN   = flag.String("role-arn", "", "Role ARN")
)

func main() {
	flag.Parse()

	handler := log15.StreamHandler(os.Stdout, log15.LogfmtFormat())
	log15.Root().SetHandler(handler)
	lgr := log15.New()

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		lgr.Error("open_tpm_err", "err", err)
		os.Exit(1)
	}
	defer tpm.Close()

	_, err = tpm.Info()
	if err != nil {
		lgr.Error("get_tpm_info_err", "err", err)
		os.Exit(1)
	}

	eks, err := tpm.EKs()
	if err != nil {
		lgr.Error("get_EKs_err", "err", err)
		os.Exit(1)
	}

	if *printEK {
		for i, ek := range eks {
			fmt.Printf("%d:\n%s\n", i, keyToPem(ek.Public))
		}
		os.Exit(0)
	}

	var ek *attest.EK
	ek = &eks[0]

OUTER:
	for _, candidateEK := range eks {
		switch candidateEK.Public.(type) {
		case *ecdsa.PublicKey:
			k := candidateEK
			ek = &k
			break OUTER
		case *rsa.PublicKey:
			k := candidateEK
			ek = &k
		default:
			lgr.Warn("unexpected_ek_key_type", "type", fmt.Sprintf("%T", candidateEK.Public))
		}
	}

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		lgr.Error("gen_ak_err", "err", err)
		os.Exit(1)
	}
	akAttestParams := ak.AttestationParameters()
	akBytes, err := ak.Marshal()
	if err != nil {
		ak.Close(tpm)
		lgr.Error("marshal_ak_err", "err", err)
		os.Exit(1)
	}
	ak.Close(tpm)

	reqChallenge := messages.RequestChallenge{
		TPMVersion:        int(attest.TPMVersion20),
		EndorsementKeyPem: keyToPem(ek.Public),
		AttestationParameters: messages.AttestationParameters{
			Public:                  akAttestParams.Public,
			UseTCSDActivationFormat: akAttestParams.UseTCSDActivationFormat,
			CreateData:              akAttestParams.CreateData,
			CreateAttestation:       akAttestParams.CreateAttestation,
			CreateSignature:         akAttestParams.CreateSignature,
		},
	}

	reqChallengeJson, err := json.Marshal(reqChallenge)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(*serverURL+"/request_challenge", "application/json", bytes.NewBuffer(reqChallengeJson))
	if err != nil {
		lgr.Error("post_challenge_err", "err", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		lgr.Error("challenge_request_err", "status", resp.StatusCode, "err", msg)
		os.Exit(1)
	}

	var challenge messages.ChallengeResponse
	err = json.NewDecoder(resp.Body).Decode(&challenge)
	if err != nil {
		lgr.Error("decode_challenge_err", "err", err)
		os.Exit(1)
	}

	encryptedCredentials := attest.EncryptedCredential{
		Credential: challenge.Credential,
		Secret:     challenge.Secret,
	}

	ak, err = tpm.LoadAK(akBytes)
	if err != nil {
		lgr.Error("load_ak_err", "err", err)
		os.Exit(1)
	}

	secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
	if err != nil {
		lgr.Error("activate_credential_err", "err", err)
		os.Exit(1)
	}

	appKey, err := tpm.NewKey(ak, nil)
	if err != nil {
		lgr.Error("new_app_key_err", "err", err)
		os.Exit(1)
	}
	defer ak.Close(tpm)

	certParams := appKey.CertificationParameters()

	proof := messages.ChallengeProof{
		ChallengeID: challenge.ChallengeID,
		Secret:      secret,
		RoleARN:     *roleARN,
		CertificationParameters: messages.CertificationParameters{
			Public:            certParams.Public,
			CreateData:        certParams.CreateData,
			CreateAttestation: certParams.CreateAttestation,
			CreateSignature:   certParams.CreateSignature,
		},
	}
	proofJson, err := json.Marshal(proof)
	if err != nil {
		panic(err)
	}

	resp, err = http.Post(*serverURL+"/prove", "application/json", bytes.NewBuffer(proofJson))
	if err != nil {
		lgr.Error("post_proof_err", "err", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		lgr.Error("proof_request_err", "status", resp.StatusCode, "err", msg)
		os.Exit(1)
	}

	var creds messages.Credentials
	err = json.NewDecoder(resp.Body).Decode(&creds)
	if err != nil {
		lgr.Error("decode_singed_cert_err", "err", err)
		os.Exit(1)
	}

	env := environ(os.Environ())
	env.Set("AWS_ACCESS_KEY_ID", *creds.Credentials.AccessKeyId)
	env.Set("AWS_SECRET_ACCESS_KEY", *creds.Credentials.SecretAccessKey)
	env.Set("AWS_SESSION_TOKEN", *creds.Credentials.SessionToken)
	env.Set("AWS_DEFAULT_REGION", creds.Region)
	env.Set("AWSESH_PROFILE", "minty-ro")
	env.Set("AWSESH_SESSION_EXPIRATION", strconv.Itoa(int(creds.Credentials.Expiration.Unix())))

	cmd := exec.Command("/bin/bash")

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, os.Interrupt, os.Kill)

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	for {
		select {
		case sig := <-sigs:
			if err := cmd.Process.Signal(sig); err != nil {
				log.Fatal(err)
				break
			}
		case err := <-waitCh:
			var waitStatus syscall.WaitStatus
			if exitError, ok := err.(*exec.ExitError); ok {
				waitStatus = exitError.Sys().(syscall.WaitStatus)
				os.Exit(waitStatus.ExitStatus())
			}
			if err != nil {
				log.Fatal(err)
			}
			return
		}
	}
}

func keyToPem(key crypto.PublicKey) string {
	marshalled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}

	canonicalPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	})

	return string(canonicalPem)
}

type environ []string

func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}

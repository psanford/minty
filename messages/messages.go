package messages

import (
	"github.com/aws/aws-sdk-go/service/sts"
)

type RequestChallenge struct {
	TPMVersion            int                   `json:"tpm_version"`
	EndorsementKeyPem     string                `json:"endorsement_key"`
	AttestationParameters AttestationParameters `json:"attestation_parameters"`
}

type AttestationParameters struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"use_tcsd_activation_format"`
	CreateData              []byte `json:"create_data"`
	CreateAttestation       []byte `json:"create_attestation"`
	CreateSignature         []byte `json:"create_signature"`
}

type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Credential  []byte `json:"credential"`
	Secret      []byte `json:"secret"`
}

type ChallengeProof struct {
	ChallengeID             string                  `json:"challenge_id"`
	Secret                  []byte                  `json:"secret"`
	CertificationParameters CertificationParameters `json:"certification_parameters"`
	RoleARN                 string                  `json:"role_arn"`
}

type Credentials struct {
	Credentials *sts.Credentials `json:"credentials"`
	Region      string           `json:"region"`
}

type CertificationParameters struct {
	Public            []byte
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}

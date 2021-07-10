package config

import (
	"os"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/inconshreveable/log15"
)

type ServerConfig struct {
	Users []User `toml:"users"`
}

type User struct {
	ID              string   `toml:"id"`
	AuthorizedRoles []string `toml:"authorized_roles"`
	EndorsementKeys []string `toml:"endorsement_keys"`
}

func LoadCloudConfig(lgr log15.Logger) *ServerConfig {
	bucketName := os.Getenv("S3_CONFIG_BUCKET")
	confPath := os.Getenv("S3_CONFIG_PATH")

	if bucketName == "" || confPath == "" {
		lgr.Error("no_s3_env_config_found")
		return nil
	}

	sess := session.Must(session.NewSession())
	s3client := s3.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})

	confResp, err := s3client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(confPath),
	})
	if err != nil {
		lgr.Error("fetch_lambda_conf_err", "err", err)
		return nil
	}

	defer confResp.Body.Close()

	var conf ServerConfig
	_, err = toml.DecodeReader(confResp.Body, &conf)
	if err != nil {
		lgr.Error("toml_config_decode_err", "err", err)
		return nil
	}

	return &conf
}

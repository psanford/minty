BIN=minty
FUNCTION_NAME=$(BIN)
BUCKET=lambda-src-sanford
VERSION=v1.0.0
CONF_BUCKET=lambda-config-sanford-io

GOBUILD_TAGS=-tags netgo,sqlite_omit_load_extension,fts5
GOBUILD_LDFLAGS=-ldflags="-extldflags=-static"
STATIC_RESOURCES=

$(BIN): $(wildcard *.go) $(wildcard **/*.go)
	go test .
	CGO_ENABLED=0 go build $(GOBUILD_LDFLAGS) $(GOBUILD_TAGS) -o $(BIN)

$(BIN).zip: $(BIN) $(STATIC_RESOURCES)
	rm -f $@
	zip -r $@ $^

.PHONY: upload
upload: $(BIN).zip
	aws lambda update-function-code --function-name $(FUNCTION_NAME) --zip-file fileb://$(BIN).zip
	rm $(BIN).zip

.PHONY: upload_s3
upload_s3: $(BIN).zip
	aws s3 cp $(BIN).zip "s3://$(BUCKET)/$(BIN)/$(VERSION)/$(BIN).zip"
	rm $(BIN).zip

.PHONY: upload_config
upload_config: $(BIN).toml
	aws s3 cp $^ "s3://$(CONF_BUCKET)/$(FUNCTION_NAME)/$(FUNCTION_NAME).toml"

.PHONY: tail_logs
tail_logs:
	cw tail /aws/lambda/$(FUNCTION_NAME) -b 5m

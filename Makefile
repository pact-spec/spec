.PHONY: all draft validate
all: validate draft
draft:
	xml2rfc --text --html draft/draft-laxsharma-pact-00.xml
validate:
	python3 tools/validate.py

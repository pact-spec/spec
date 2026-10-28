.PHONY: all draft validate
all: validate draft
draft:
	xml2rfc --text --html draft/draft-laxsharma-pact-00.xml
	xml2rfc --text --html draft/draft-laxsharma-pact-01.xml
	xml2rfc --text --html draft/draft-laxsharma-pact-02.xml
	xml2rfc --text --html draft/draft-laxsharma-pact-03.xml
validate:
	python3 tools/validate.py

sam build
sam package --s3-bucket bikelaneapp-sam-test --output-template-file packaged.yaml
sam deploy --template-file packaged.yaml --stack-name bikelaneapp-api --capabilities CAPABILITY_IAM

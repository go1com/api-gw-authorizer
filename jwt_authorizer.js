'use strict'

let nJwt = require('njwt')
let AWS = require('aws-sdk')
let AuthPolicy = require('./auth_policy')

exports.handler = function (event, context) {
  let kms = new AWS.KMS()

    // JWT_SECRET must be encoded in base64 beforehand
  let decryptionParams = {
    CiphertextBlob: new Buffer(process.env.JWT_SECRET, 'base64')
  }

  kms.decrypt(decryptionParams, function (err, data) {
    if (err) {
      context.fail('Unauthorized')
    } else {
      let key = data.Plaintext
      try {
        let verifiedJwt = nJwt.verify(event.authorizationToken, key)
        let apiOptions = {}
        let tmp = event.methodArn.split(':')
        let apiGatewayArnTmp = tmp[5].split('/')
        let awsAccountId = tmp[4]
        apiOptions.region = tmp[3]
        apiOptions.restApiId = apiGatewayArnTmp[0]
        apiOptions.stage = apiGatewayArnTmp[1]

        let policy = new AuthPolicy(verifiedJwt.body.sub, awsAccountId, apiOptions)

        policy.allowAllMethods()
        context.succeed(policy.build())
      } catch (ex) {
        context.fail('Unauthorized')
      }
    }
  })
}

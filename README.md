# democustomauthserver
democustomauthserver

curl --location --request POST 'http://localhost:9990/democustomauthserver/signup' \
--header 'Content-Type: application/json' \
--data-raw '{ "userName": "test1234", 
"password":"test1234"
}'

curl --location --request GET 'http://localhost:9990/democustomauthserver/ping' \
--header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtd2FsbGV0MmdvIiwic3ViIjoidGVzdDEyMzQiLCJleHAiOjE2MjYyNzI2MTQsImlhdCI6MTYyNjI3MTcxNH0.jzW9tKZjXY4-1FaWqqgmE2n2z8UUM2EPHkdv3TO-3wGLFG5w_z4-cy19EyL5Nk-CtWXScEaEqyiuh3TsyeiAxYkEhbypXmiUOnGp5XVPG38qm-HUVGXGCsCizOoVLtSEOzWudIPuWlTk_P2NNM8M27VGhBUxUyeLBwfVz_c9uDiwuYmz7BjDOFTGheFMzDp5YBeHlsBR1w3LS1esphb-lOvi-X_I2n7YObbecz2V4CgYjs2vTS5zh4SoPOCXOCTIxn68JXPKIXV5sA7Ye5a2pGD_N8mnvDmal0twIrJajysHx5CqScuV0-zlWK3nabkahGW1_Rqes6AtMfSqY7P7tg'

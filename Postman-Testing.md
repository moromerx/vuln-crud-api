# Postman Testing
### Testing each endpoint with Postman:

*GET /vulnerabilities — Get All*
![GET ALL](/images/GET_ALL.png)

*GET /vulnerabilities/{id} — Get By ID (valid UUID, exists)*
![GET_ID_VALIDPATH](/images/GET_ID_VALIDPATH.png)

*GET /vulnerabilities/{id} — Get By ID (invalid UUID format)*
![GET_ID_WRONGUUID](/images/GET_ID_WRONGUUID.png)

*GET /vulnerabilities/{id} — Get By ID (valid UUID, not found)*
![GET_ID_NOTFOUND](/images/GET_ID_NOTFOUND.png)

*POST /vulnerabilities — Create*
![CREATE](/images/CREATE.png)

*POST /vulnerabilities — Create (missing required CVE)*
![CREATE_MISSINGCVE](/images/CREATE_MISSINGCVE.png)

*DELETE /vulnerabilities/{id} — Delete*
![DELETE](/images/DELETE.png)

*PUT /vulnerabilities/{id} — Update*
![UPDATE](/images/UPDATE.png)


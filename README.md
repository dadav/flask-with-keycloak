# Authlib with keycloak

## how to run this

```bash
# start keycloak
podman run --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:17.0.1 start-dev

# create a realm and export the variable
# example: realm=demo
KEYCLOAK_ISSUER="http://localhost:8080/realms/demo"

# create a client
# example: flaskapp
KEYCLOAK_CLIENTID=flaskapp
# set it to confidental, click on the authorization tab and export the variable
KEYCLOAK_SECRET=$secret
# set the redirection url to http://localhost:5000/callback

# and don't forget to set the registration of the realm to true, so you can
# create users
# additional: create a admin role and asign it to one user

# now just run the app
source ./venv/bin/activate
flask run
```

# embiam
Embedded identity and access management

-- WHAT IS embiam?
The idea is to embed IAM directly in your API server. Since IAM doesn't require much CPU power or RAM, it's obvious to combine the primary tasks in your APIS and IAM. Use embiam to make your IAM simpler, easier to maintain, and more efficient. Efficiency doesn't only lead to cost reduction on your cloud infrastructure but also to greener IT because it's using less energy. With higher efficiency you also improve your user's expericence because the reponse times shrink and your user's have a smoother and more reactive experince using your applications. #CodeGreenIT

-- HOW DO YOU USE IT?

-- Checking identities 
Just embed embiam in your API code and use it to check username (we call it nick) and password. Provide an API that receives username (we call it nick) and password to validate it. If the validation was successful, send a token back to the client application. With this identity token all other steps of the session are validated.

    identityToken, err := embiam.CheckIdentity(credentials.Nick, credentials.Password, clientHost)
see example 3 

-- Secure APIs with identity tokens
After the authentication (with nick and password) the client application gets an identity token. This is used to validate the calls to your APIs. Before the acutal task of the API is started, the identity token is checked. When the check was successful the actual task can be done, e.g. the data is fechted from the db or the item is added to the shopping basket. Just add the identityToken to your interface and check it in your APIs coding:

	if !embiam.IsIdentityTokenValid(requestBody.IdentityToken, clientHost) {
		http.Error(w, "", http.StatusForbidden)
		return
	}
see example 3 

-- Creating new nicks
We call it nick instead of user because a nick describes also a machine, not only person. 
Nicks are generated and can't be choosen. So is the password. The procedure to provide a new identity, a new nick is as follows
	1. A nick token is generated. The nick token is valid for a certain time (e.g. 3 days). Usually the admin generates the token and sends it to the new user.
	   embiam.GetNickToken() nickToken

	2. The new user receives the nick token and uses it to get a new nick, a new password and a secret (to restore passwords). At the same time embiam saves the new nick in db (for password and secret embiam only stores hashes). The nick token is deleted.
	   embiam.GenerateNewNick(nickToken) newNick
package templates

import "html/template"

// nolint:gocheckglobals
// IndexTemplate is HTML template for index page.
var IndexTemplate, _ = template.New("index").Parse(`
	<html>
	<head><title>Test page</title></head>
	<body>
		<h1>OTP Test page</h1>
		<form action="/" method="GET" target="result" >
			OTP: <input type="text" maxlength="44"  name="otp" style="width: 300px"/><input type="submit"/>
		</form>
		<pre  width="500" height="150" style="border: 1px solid #666">{{.Result}}</pre>
	</body>
	</html>
`)

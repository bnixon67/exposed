# Exposed

The `exposed` package provides utilities to check if a password or its hash has been exposed in breaches using the Have I Been Pwned API.

## Checking a Password

You can check if a password has been exposed in breaches by using the CheckPwnedPassword function. This function supports both SHA-1 and NTLM hash modes.

## Checking a Hash

If you already have a hash of the password, you can use the CheckPwnedHash function directly.

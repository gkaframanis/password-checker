import requests
import hashlib
import sys


# The API of https://haveibeenpawned.com for the password uses SHA1 hashing.
# We need to send the hashed version to the API, but this is not secure, so: https://en.wikipedia.org/wiki/K-anonymity
# We give only the 5 first characters of our hashed password (BAB1298D948EBB34BD0F3FAF5E596EBC0B27C615)
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    response = requests.get(url)
    # With the response data we can for our exact password.
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, check the API and try again.")
    return response


def get_password_leaks_count(hashes, hash_to_check):
    # We get a list for each line with the tail hash and the count values.
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # We use the built-in library hashlib to create the hashed version version of our password. 
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_chars, tail = sha1password[:5], sha1password[5:]
    # response.text gives a load of hash_tail:count lines.
    response = request_api_data(first5_chars)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"The {password} password was found {count} times... You should probably change your password.")
        else:
            print(f"The {password} password was NOT found. Carry on!")
    return "Done!"


if __name__ == '__main__':
    # To exit the entire process and get the return value of the main() function.
    sys.exit(main(sys.argv[1:]))
# SHA1 Hash Generator
import requests 
import hashlib #for hashing the input
import sys



def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char #SHA1 hashed password
  #k-anonymity: use first 5 letter of hashed password
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res

#return response will give the hashstrings (tail and count ) from the API that matched ours
#this is obtained when we do hashes.text. Converts the response to text
#Now we need to seperate the tail and count and match the tail with our tail and 
# return the count
def get_password_leaks_count(hashes, hash_to_check):
	#split the response by the ':' # splitlines returns a list of lines in the string, breaking 
	#at line boundary, ex: ['FEJFJSDSD...', 'count']
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes: 
    if h == hash_to_check: #if tail of hash.text match the tail we have
      return count
  return 0 # else return 0

#check password if it exists in API response
def pwned_api_check(password):
	#convert password to SHA1 hash and convert it to upper case hexadecimal
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  	#first 5 char is the hash string we will check, rest are tail. This remains on out comp
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)


def main(args):
  for password in args:
    count = pwned_api_check(password)
    if count:
      print(f'{password} was found {count} times... you should probably change your password!')
    else:
      print(f'{password} was NOT found. Carry on!')
  return 'done!'

if __name__ == '__main__': #only run the main file 
  sys.exit(main(sys.argv[1:]))

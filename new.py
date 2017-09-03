import requests
def snd():
    data = {
       'apikey': '03ec627c-61db-4fee-9f2c-8319c424ad39',
       'subject': 'Your Subject',
       'from': 'Security@palware.com',
       'fromName': 'Your Company Name',
       'to': 'ros3.dev@gmail.com',
       'bodyHtml': "< h1 > HtmlBody < / h1 >",
       'bodyText': 'Text Body',
       'isTransactional': False
    }

    url = 'https://api.elasticemail.com/v2/email/send'
    result = requests.post(url, params=data).json()

    if result['success'] is False:
        return result['error']

    return result['data']


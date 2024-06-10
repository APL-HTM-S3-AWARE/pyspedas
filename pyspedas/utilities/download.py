import os
import re
import sys
import warnings
import requests
import logging
import fnmatch
import datetime
import pkg_resources
import fsspec

from pathlib import Path
from shutil import copyfileobj, copy
from tempfile import NamedTemporaryFile
from html.parser import HTMLParser
from netCDF4 import Dataset
from cdflib import CDF
from time import sleep
import fsspec

def is_fsspec_uri(uri):
    '''
    See if uri is something fsspec can handle.
    Pulled from Pandas:
        https://github.com/pandas-dev/pandas/blob/main/pandas/io/common.py#L291
    '''
    _RFC3896_ = re.compile(r"^[A-Za-z][A-Za-z0-9+\-+.]*://")
    return (
            isinstance(uri, str)
            and bool(_RFC3896_.match(uri))
            and not uri.startswith(('http://', 'https://'))
    )

# the following is used to parse the links from an HTML index file
class LinkParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            attrs = {k: v for (k, v) in attrs}
            if 'href' in attrs:
                link = attrs['href']
                # kludge to support http://rbspice?.ftecs.com/
                if '/' in link:
                    link = link.split('/')[-1]
                try:
                    self.links.append((link))
                except AttributeError:
                    self.links = [(link)]

def check_downloaded_file(filename):
    """
    Check if a file exists and if it can be opened (for CDF and netCDF files).

    If the file exists but it is not CDF or netCDF, it returns True without trying to open the file.
    """
    result = False
    if is_fsspec_uri(filename):
        # note: currently cdflib only supports S3
        protocol, path = filename.split('://')
        fs = fsspec.filesystem(protocol, anon=False)

        # AWS cdflib support currently
        # https://github.com/MAVENSDC/cdflib/blob/main/cdflib/cdfread.py#L77
        try:
            cdf_file = CDF(filename)
            return True
        except:
            logging.info("Cannot open CDF file: " + filename)
            return False

    fpath = Path(filename)
    if fpath.is_file() and len(filename) > 3:
        if filename[-4:] == '.cdf':
            # Try to open the cdf file
            try:
                cdf_file = CDF(filename)
                result = True
            except:
                logging.info("Cannot open CDF file: " + filename)
                result = False
        elif filename[-3:] == '.nc':
            # Try to open the netCDF file
            try:
                netcdf_file = Dataset(filename)
                result = True
            except:
                logging.info("Cannot open netCDF file: " + filename)
                result = False
        else:
            # The file is not CDF or netCDF, print a warning and return true
            logging.info("The file is not CDF or netCDF. Filename: " + filename)
            result = True

    return result


def download_file(url=None,
                  filename=None,
                  headers={},
                  username=None,
                  password=None,
                  verify=False,
                  session=None,
                  basic_auth=False,
                  nbr_tries=0):
    """
    Download a file and return its local path; this function is primarily meant to be called by the download function

    Parameters:
        url: str
            Remote URL to download

        filename: str
            Local file name

        headers: dict
            Dictionary containing the headers to be passed to the requests get call

        username: str
            Username to be used in HTTP authentication

        password: str
            password to be used in HTTP authentication

        verify: bool
            Flag indicating whether to verify the SSL/TLS certificate

        session: requests.Session object
            Requests session object that allows you to persist things like HTTP authentication through multiple calls

        nbr_tries: int
            Counts how many times we tried to download the file. Default is 0.

    Notes:
        Checks if the CDF or netCDF file can be opened, and if it can't, tries to download the file for a second time.

    Returns:
        String containing the local file name

    """
    headers_original = headers
    session_original = session

    if session is None:
        session = requests.Session()

    if username is not None:
        session.auth = requests.auth.HTTPDigestAuth(username, password)

    # Cloud Awareness
    if is_fsspec_uri(url):
        protocol, path = url.split('://')
        rfs = fsspec.filesystem(protocol, anon=False)

        if is_fsspec_uri(filename):
            lprotocol, lpath = filename.split('://')
            lfs = fsspec.filesystem(protocol, anon=False)

            # url and filename are both S3 paths
            if lfs.exists(filename):
                lmod_tm = (lfs.info(lpath)['LastModified']).strftime('%a, %d %b %Y %H:%M:%S GMT')
                rmod_tm = (rfs.info(path)['LastModified']).strftime('%a, %d %b %Y %H:%M:%S GMT')

                if lmod_tm >= rmod_tm:
                    logging.info('File is current: ' + filename)
                else:
                    # copy newer remote file
                    logging.info('Retrieving newer remote file: ' + url)
                    rfs.get(url, os.getcwd())
                    lpath = os.path.join(os.getcwd(), url[url.rfind('/')+1:])
                    lfs.put(lpath, filename)
                    logging.info('File placed on "local": ' + filename)
                    os.remove(lpath)
            return filename
        else:
            needs_to_download = True
            # only case where user is downloading from S3 to local
            if os.path.exists(filename):
                # compare modification times of files to avoid re-downloading
                # files that haven't changed
                mod_tm = (datetime.datetime.utcfromtimestamp(os.path.getmtime(filename))).strftime('%a, %d %b %Y %H:%M:%S GMT')
                rmod_tm = (rfs.info(path)['LastModified']).strftime('%a, %d %b %Y %H:%M:%S GMT')

                if mod_tm >= rmod_tm:
                    logging.info('File is current: ' + filename)
                    needs_to_download = False
            if needs_to_download:
                logging.info('Downloading ' + url + ' to ' + filename)

                # remote fsspec get/download file to local
                rfs.get(url, filename)

                logging.info('Download complete: ' + os.path.basename(filename))

        # At this point, we check if the file can be opened.
        # If it cannot be opened, we delete the file and try again.
        if nbr_tries == 0 and check_downloaded_file(filename) == False:
            nbr_tries = 1
            logging.info('There was a problem with the file: ' + filename)
            logging.info('We are going to download it for a second time.')
            if os.path.exists(filename):
                os.unlink(filename)
    
            download_file(url=url,
                          filename=filename,
                          headers=headers_original,
                          username=username,
                          password=password,
                          verify=verify,
                          session=session_original,
                          basic_auth=basic_auth,
                          nbr_tries=nbr_tries)
    
        # If the file again cannot be opened, we give up.
        if nbr_tries > 0 and check_downloaded_file(filename) == False:
            nbr_tries = 2
            logging.info('Tried twice. There was a problem with the file: ' + filename)
            logging.info('File will be removed. Try to download it again at a later time.')
            if os.path.exists(filename):
                os.unlink(filename)
            filename = None
        return filename

    # url is not fsspec URI

    if is_fsspec_uri(filename):
        protocol, path = filename.split('://')
        fs = fsspec.filesystem(protocol, anon=False)

        if fs.exists(filename):
            mod_tm = (fs.info(path)['LastModified']).strftime('%a, %d %b %Y %H:%M:%S GMT')
            headers['If-Modified-Since'] = mod_tm
    else:
        # check if the file exists, and if so, set the last modification time in the header
        # this allows you to avoid re-downloading files that haven't changed
        if os.path.exists(filename):
            mod_tm = (datetime.datetime.utcfromtimestamp(os.path.getmtime(filename))).strftime('%a, %d %b %Y %H:%M:%S GMT')
            headers['If-Modified-Since'] = mod_tm

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=ResourceWarning)
        if not basic_auth:
            fsrc = session.get(url, stream=True, verify=verify, headers=headers)
        else:
            fsrc = session.get(url, stream=True, verify=verify, headers=headers, auth=(username, password))

    # need to delete the If-Modified-Since header so it's not set in the dictionary in subsequent calls
    if headers.get('If-Modified-Since') is not None:
        del headers['If-Modified-Since']

    needs_to_download_file = False
    if fsrc.status_code == 304:
        # the file hasn't changed
        logging.info('File is current: ' + filename)
        fsrc.close()
    elif fsrc.status_code == 404:
        # file not found
        logging.error('Remote file not found: ' + url)
        fsrc.close()
        return None
    elif fsrc.status_code == 401 or fsrc.status_code == 403:
        # authentication issues
        logging.error('Unauthorized: ' + url)
        fsrc.close()
        return None
    elif fsrc.status_code == 200:
        # this is the main download case
        needs_to_download_file = True
        logging.info('Downloading ' + url + ' to ' + filename)
    else:
        # all other problems
        logging.error(fsrc.reason)
        fsrc.close()
        return None

    if needs_to_download_file:
        ftmp = NamedTemporaryFile(delete=False)

        with open(ftmp.name, 'wb') as f:
            copyfileobj(fsrc.raw, f)

        if is_fsspec_uri(filename):
            protocol, path = filename.split('://')
            fs = fsspec.filesystem(protocol, anon=False)

            # copy method is within filesystems under fsspec
            fs.put(ftmp.name, filename)
        else:
            # make sure the directory exists
            if not os.path.exists(os.path.dirname(filename)) and os.path.dirname(filename) != '':
                os.makedirs(os.path.dirname(filename))
    
            # if the download was successful, copy to data directory
            copy(ftmp.name, filename)

        fsrc.close()
        ftmp.close()
        os.unlink(ftmp.name)  # delete the temporary file

        logging.info('Download complete: ' + os.path.basename(filename))

    # At this point, we check if the file can be opened.
    # If it cannot be opened, we delete the file and try again.
    if nbr_tries == 0 and check_downloaded_file(filename) == False:
        nbr_tries = 1
        logging.info('There was a problem with the file: ' + filename)
        logging.info('We are going to download it for a second time.')
        if is_fsspec_uri(filename):
            fs = fsspec.filesystem(protocol, anon=False)
            fs.delete(filename)
        elif os.path.exists(filename):
            os.unlink(filename)

        download_file(url=url,
                      filename=filename,
                      headers=headers_original,
                      username=username,
                      password=password,
                      verify=verify,
                      session=session_original,
                      basic_auth=basic_auth,
                      nbr_tries=nbr_tries)

    # If the file again cannot be opened, we give up.
    if nbr_tries > 0 and check_downloaded_file(filename) == False:
        nbr_tries = 2
        logging.info('Tried twice. There was a problem with the file: ' + filename)
        logging.info('File will be removed. Try to download it again at a later time.')
        if is_fsspec_uri(filename):
            fs = fsspec.filesystem(protocol, anon=False)
            fs.delete(filename)
        elif os.path.exists(filename):
            os.unlink(filename)
        filename = None

    return filename


def download(remote_path='',
             remote_file='',
             local_path='',
             local_file='',
             headers={},
             username=None,
             password=None,
             verify=True,
             session=None,
             no_download=False,
             last_version=False,
             basic_auth=False,
             regex=False,
             no_wildcards=False):
    """
    Download one or more remote files and return their local paths.

    Parameters:
        remote_path: str
            String consisting of a common URL base for all remote files

        remote_file: str or list of str
            String or string array of URLs to remote files

        local_path: str
            String consisting of a common local path for all local files

        local_file: str or list of str
            String or string array of local destination file names

        headers: dict
            Dictionary containing the headers to be passed to the requests get call

        username: str
            Username to be used in HTTP authentication

        password: str
            Password to be used in HTTP authentication

        basic_auth: bool
            Flag to indicate that the remote server uses basic authentication
            instead of digest authentication

        verify: bool
            Flag indicating whether to verify the SSL/TLS certificate

        session: requests.Session object
            Requests session object that allows you to persist things like HTTP authentication through multiple calls

        no_download: bool
            Flag to not download remote files

        last_version: bool
            Flag to only download the last in file in a lexically sorted
            list when multiple matches are found using wildcards

        regex: bool
            Flag to allow regular expressions in the file name matching,
            instead of unix style matching

        no_wildcards: bool
            Flag to assume no wild cards in the requested url/filename

    Returns:
        String list specifying the full local path to all requested files

    """
    local_file_in = local_file

    if isinstance(remote_path, list):
        logging.error('Remote path must be a string')
        return

    if isinstance(local_path, list):
        logging.error('Local path must be a string')
        return

    if local_path == '':
        local_path = str(Path('').resolve())

    if username is not None and password is None:
        logging.error('Username provided without password')
        return

    if session is None:
        session = requests.Session()

    if username is not None:
        session.auth = requests.auth.HTTPDigestAuth(username, password)

    if headers.get('User-Agent') is None:
        try:
            release_version = pkg_resources.get_distribution("pyspedas").version
        except pkg_resources.DistributionNotFound:
            release_version = 'bleeding edge'
        headers['User-Agent'] = 'pySPEDAS ' + release_version

    out = []
    index_table = {}

    # To avoid hammering the remote server with repeated failing requests, if we have a problem with an index
    # URL we'll add it to bad_index_set and skip it if it comes up again.
    bad_index_set = set()

    if not isinstance(remote_file, list):
        remote_file = [remote_file]

    urls = [remote_path+rfile for rfile in remote_file]

    for url in urls:
        resp_data = None
        url_file = url[url.rfind("/")+1:]
        url_base = url.replace(url_file, '')

        # automatically use remote_file locally if local_file is not specified
        if local_file_in == '':
            # if remote_file is the entire url then only use the filename
            if remote_path == '':
                local_file = url_file
            else:
                local_file = url.replace(remote_path, '')

                if local_file == '':  # remote_path was the full file name
                    local_file = remote_path[remote_path.rfind("/")+1:]

        filename = os.path.join(local_path, local_file)

        short_path = local_file[:1+local_file.rfind("/")]

        if is_fsspec_uri(url) and no_download:
            # this is the case where a user wants to download to local
            # from a URI (NOT RECOMMENDED)
            #print('NOT RECOMMENDED!')
            protocol, path = url.split('://')
            fs = fsspec.filesystem(protocol, anon=False)

            links = [link[link.rfind('/')+1:] for link in fs.glob(url)]
            # download the files
            for new_link in links:
                resp_data = download(remote_path=remote_path, remote_file=short_path+new_link,
                                     local_path=local_path, username=username, password=password,
                                     verify=verify, headers=headers, session=session, basic_auth=basic_auth)
                if resp_data is not None:
                    for file in resp_data:
                        out.append(file)
            continue


        if not no_download:
            # expand the wildcards in the url
            if ('?' in url or '*' in url or regex) and (not no_download and not no_wildcards):
                if index_table.get(url_base) is not None and not is_fsspec_uri(url):
                    links = index_table[url_base]
                elif url_base in bad_index_set:
                    logging.info('Skipping remote index: ' + url_base + ' (previous attempt failed)')
                    continue
                elif is_fsspec_uri(url):
                    # when remote is URI, do not download data / read in place
                    protocol, path = url.split('://')
                    fs = fsspec.filesystem(protocol, anon=False)

                    if not is_fsspec_uri(local_path):
                        resp_data = [protocol + '://' + link for link in fs.glob(url)]
                        for link in resp_data:
                            logging.info('Using remote URI file: '+link)
                            out.append(link)
                        continue
                    else:
                        # local is URI so we are just updating files between URIs
                        if index_table.get(url_base) is None:
                            logging.info('Retrieving listings from directory: ' + url_base)
                        else:
                            # reset since we glob for specific files instead of a full directory listing
                            index_table = {}
                        links = [link[link.rfind('/')+1:] for link in fs.glob(url)]
                        index_table[url_base] = links
                else:
                    logging.info('Downloading from remote index: ' + url_base)

                    # we'll need to parse the HTML index file for the file list
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", category=ResourceWarning)
                        try:
                            if not basic_auth:
                                html_index = session.get(url_base, verify=verify, headers=headers)
                            else:
                                html_index = session.get(url_base, verify=verify, headers=headers, auth=(username, password))
                        except requests.exceptions.ConnectionError:
                            # Add this index to bad_index_set and cool down a bit
                            bad_index_set.add(url_base)
                            sleep(2)
                            continue

                    if html_index.status_code == 404:
                        logging.error('Remote index not found: ' + url_base)
                        # Add this index to bad_index_set and cool down a bit
                        bad_index_set.add(url_base)
                        sleep(2)
                        continue

                    if html_index.status_code == 401 or html_index.status_code == 403:
                        logging.error('Unauthorized: ' + url_base)
                        # Add this index to bad_index_set and cool down a bit
                        bad_index_set.add(url_base)
                        sleep(2)
                        continue

                    # grab the links
                    link_parser = LinkParser()
                    link_parser.feed(html_index.text)

                    try:
                        links = link_parser.links
                        index_table[url_base] = links
                    except AttributeError:
                        links = []

                # find the file names that match our string
                if not regex:
                    # note: fnmatch.filter accepts ? (single character) and * (multiple characters)
                    new_links = fnmatch.filter(links, url_file)
                else:
                    reg_expression = re.compile(url_file)
                    new_links = list(filter(reg_expression.match, links))

                if len(new_links) == 0:
                    logging.info("No links matching pattern %s found at remote index %s", url_file, url_base)

                if last_version and len(new_links) > 1:
                    new_links = sorted(new_links)
                    new_links = [new_links[-1]]

                if '?' in remote_path or '*' in remote_path:
                    # the user specified a wild card in the remote_path
                    remote_path = url_base

                # download the files
                for new_link in new_links:
                    resp_data = download(remote_path=remote_path, remote_file=short_path+new_link,
                                         local_path=local_path, username=username, password=password,
                                         verify=verify, headers=headers, session=session, basic_auth=basic_auth)
                    if resp_data is not None:
                        for file in resp_data:
                            out.append(file)
                session.close()
                continue
            resp_data = download_file(url=url, filename=filename, username=username, password=password, verify=verify,
                                      headers=headers, session=session, basic_auth=basic_auth)

        if resp_data is not None:
            if not isinstance(resp_data, list):
                resp_data = [resp_data]
            for file in resp_data:
                out.append(file)
        else:
            # download wasn't successful, search for local files
            logging.info('Searching for local files...')
            
            temp_out = []
            
            if local_path == '':
                local_path_to_search = str(Path('.').resolve())
            else:
                local_path_to_search = local_path

            for dirpath, dirnames, filenames in os.walk(local_path_to_search):
                local = local_file[local_file.rfind("/")+1:]
                if not regex:
                    matching_files = fnmatch.filter(filenames, local)
                else:
                    reg_expression = re.compile(local)
                    matching_files = list(filter(reg_expression.match, filenames))

                for file in matching_files:
                    # out.append(os.path.join(dirpath, file))
                    temp_out.append(os.path.join(dirpath, file))
                                
            # check if the file exists, and if so, set the last modification time in the header
            if len(temp_out) == 0:
                logging.info('No local files found for ' + url)
                continue
            temp_out = sorted(temp_out)
            
            if last_version:
                out.append(temp_out[-1]) # append the latest version
            else:
                for file in temp_out:
                    out.append(file)


    session.close()
    return out

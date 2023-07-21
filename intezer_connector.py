import json
import os
import shutil
import uuid

import requests
from intezer_sdk.alerts import Alert
from intezer_sdk.analysis import FileAnalysis, UrlAnalysis
from intezer_sdk.api import get_global_api, set_global_api
from intezer_sdk.consts import AnalysisStatusCode, IndexType
from intezer_sdk.errors import AnalysisIsAlreadyRunningError, AnalysisIsStillRunningError, HashDoesNotExistError, IntezerError
from intezer_sdk.index import Index
from requests.exceptions import HTTPError

from intezer_consts import INTEZER_JSON_APIKEY

try:
    import phantom.app as phantom
    import phantom.rules as ph_rules
    from phantom.app import ActionResult, BaseConnector
    from phantom.vault import Vault
except ImportError:
    pass


class IntezerConnector(BaseConnector):
    def __init__(self):
        super(IntezerConnector, self).__init__()
        self.api = None
        self.intezer_action_result = None
        self._intezer_api_key = None
        self.action_mapper = {
            'test_connectivity': self.test_connectivity,
            'detonate_file': self.detonate_file,
            'detonate_hash': self.detonate_hash,
            'get_file_report': self.get_file_report,
            'detonate_url': self.detonate_url,
            'get_url_report': self.get_url_report,
            'get_alert': self.get_alert,
            'index_file': self.index_file,
            'unset_index_file': self.unset_index_file,
        }

    def test_connectivity(self, **kwargs):
        """Test the connection to Intezer."""
        phantom.debug('Testing connectivity to Intezer')
        try:
            is_available = self.api.is_available()
        except IntezerError:
            is_available = False
        if is_available:
            self.intezer_action_result.add_data({'is_available': False})
            self.intezer_action_result.update_summary({'is_available': False})
        else:
            self.intezer_action_result.add_data({'is_available': True})
            self.intezer_action_result.update_summary({'is_available': True})
        phantom.debug_print('Test connectivity result: {}'.format(is_available))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def detonate_url(self, url: str, **kwargs):
        """
        Detonate a url.

        :param url: The url to analyze.
        """
        phantom.debug('Detonating url: {}'.format(url))
        url_analysis = UrlAnalysis(url=url)
        try:
            url_analysis.send(requester='splunk_soar')
        except IntezerError as e:
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'URL analysis failed - {e}')
        result = {'analysis_id': url_analysis.analysis_id,
                  'analysis_status': url_analysis.status.value,
                  'analysis_type': 'url',
                  'identifier': url}

        self.intezer_action_result.add_data(result)
        self.intezer_action_result.update_summary(result)
        phantom.debug('Detonate url result: {}'.format(result))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def detonate_hash(self, file_hash: str, **kwargs):
        """
        Detonate a hash.

        :param file_hash: hash to analyze.
        """
        phantom.debug('Detonating hash: {}'.format(file_hash))
        file_analysis = FileAnalysis(file_hash=file_hash)
        try:
            file_analysis.send(requester='splunk_soar')
        except IntezerError as e:
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'File analysis failed - {e}')
        result = {'analysis_id': file_analysis.analysis_id,
                  'analysis_status': file_analysis.status.value,
                  'analysis_type': 'file',
                  'identifier': file_hash}
        self.intezer_action_result.add_data(result)
        self.intezer_action_result.update_summary(result)

        phantom.debug('Detonate hash result: {}'.format(result))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def detonate_file(self, vault_id: str, **kwargs):
        """
        Detonate a file.

        :param vault_id: The vault id of the file to analyze.
        """
        phantom.save_progress('Detonating file: {}'.format(vault_id))
        file_path, status = self._locate_file_path(vault_id)
        if status != phantom.APP_SUCCESS:
            return self.intezer_action_result.set_status(status)
        file_analysis = FileAnalysis(file_path=file_path)
        try:
            file_analysis.send(requester='splunk_soar')
        except IntezerError as e:
            phantom.save_progress(f'File analysis failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'File analysis failed - {e}')
        result = {'analysis_id': file_analysis.analysis_id,
                  'analysis_status': file_analysis.status.value,
                  'analysis_type': 'file',
                  'identifier': vault_id}
        self.intezer_action_result.add_data(result)
        self.intezer_action_result.update_summary(result)
        phantom.save_progress('Detonate file result: {}'.format(result))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def index_file(self, index_as: str, sha256: str, family_name: str = None, **kwargs):
        """
        Index a file.

        :param index_as: The index type.
        :param sha256: The hash of the file to index.
        :param family_name: The family name of the file to index.
        """
        phantom.save_progress('Indexing file: {}'.format(sha256))
        index_as = IndexType.from_str(index_as)
        index = Index(index_as=index_as,
                      sha256=sha256,
                      family_name=family_name)
        try:
            index.send(wait=True)
        except IntezerError as e:
            phantom.save_progress(f'Index file failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Index file failed - {e}')
        self.intezer_action_result.add_data({'index_id': index.index_id})
        self.intezer_action_result.update_summary({'index_id': index.index_id})
        phantom.save_progress('Index file result: {}'.format(index.index_id))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def unset_index_file(self, file_hash: str, **kwargs):
        """
        Unset the indexing of a hash.

        :param file_hash: The hash of the file to unset indexing.
        """
        phantom.save_progress('Unset indexing of file: {}'.format(file_hash))
        index = Index(index_as=IndexType.TRUSTED,
                      sha256=file_hash)
        try:
            index.unset_indexing(wait=True)
        except IntezerError as e:
            phantom.save_progress(f'Unset index file failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Unset index file failed - {e}')
        phantom.save_progress('Unset index file result: {}'.format(index.index_id))
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def get_file_report(self, analysis_id: str = None, file_hash: str = None, private_only: bool = False,
                        wait_for_completion: bool = True, **kwargs):
        """
        Get the file report according to analysis_id or hash.

        :param analysis_id: The analysis id of the desired report.
        :param file_hash: The hash of the desired report.
        :param private_only: Whether to show only private reports (relevant only for hashes).
        :param wait_for_completion: Whether to wait for the analysis to complete before returning the report.
        """
        phantom.save_progress('Getting file report')
        if not analysis_id and not file_hash:
            return self.intezer_action_result.set_status(phantom.APP_ERROR,
                                                         'Must specify either analysis id or hash')
        try:
            base_summary = {'analysis_id': analysis_id, 'analysis_type': 'file'}
            if file_hash:
                file_analysis = None
                try:
                    file_analysis = FileAnalysis.from_latest_hash_analysis(file_hash,
                                                                           private_only=private_only,
                                                                           requester='splunk_soar')
                except HTTPError:
                    pass

                if not file_analysis:
                    file_analysis = FileAnalysis(file_hash=file_hash)
                    try:
                        file_analysis.send(requester='splunk_soar')
                    except AnalysisIsAlreadyRunningError as ex:
                        file_analysis = FileAnalysis.from_analysis_id(ex.analysis_id)
                    except HashDoesNotExistError:
                        phantom.save_progress(f'Hash {file_hash} does not exist')
                        return self.intezer_action_result.set_status(phantom.APP_ERROR,
                                                                     f'Hash {file_hash} does not exist')
            else:
                file_analysis = FileAnalysis.from_analysis_id(analysis_id)

            if wait_for_completion:
                file_analysis.wait_for_completion()
        except IntezerError as e:
            phantom.save_progress(f'Get file report failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Get file report failed - {e}')
        if file_analysis.status != AnalysisStatusCode.FINISHED:
            self.intezer_action_result.add_data(
                {**base_summary, 'analysis_status': file_analysis.status.value, 'analysis_content': {}})
            self.intezer_action_result.update_summary(
                {**base_summary, 'analysis_status': file_analysis.status.value, 'analysis_content': {}})
            phantom.save_progress('File analysis is still running')
            return self.intezer_action_result.set_status(phantom.APP_SUCCESS)
        try:
            analysis = {
                'analysis': file_analysis.result(),
                'iocs': file_analysis.iocs,
                'ttps': file_analysis.dynamic_ttps,
                'metadata': file_analysis.get_root_analysis().metadata,
                'root-code-reuse': file_analysis.get_root_analysis().code_reuse,
            }
        except AnalysisIsStillRunningError:
            self.intezer_action_result.add_data(
                {**base_summary, 'analysis_status': AnalysisStatusCode.IN_PROGRESS.value})
            self.intezer_action_result.update_summary(
                {**base_summary, 'analysis_status': AnalysisStatusCode.IN_PROGRESS.value})
            phantom.save_progress('File analysis is still running')
            return self.intezer_action_result.set_status(phantom.APP_SUCCESS)
        except IntezerError as e:
            phantom.save_progress(f'Get file report failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Get file report failed - {e}')
        result = {**base_summary,
                  'analysis_status': AnalysisStatusCode.FINISHED.value,
                  'analysis_content': analysis}
        self.intezer_action_result.add_data(result)
        self.intezer_action_result.update_summary(result)

        phantom.save_progress('File analysis finished')
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def get_url_report(self, analysis_id: str, wait_for_completion=True, **kwargs):
        """
        Get the url report according to analysis_id.
        :param analysis_id: The analysis id of the desired report.
        :param wait_for_completion: Whether to wait for the analysis to finish.
        """
        phantom.save_progress('Getting url report')
        try:
            base_summary = {'analysis_id': analysis_id, 'analysis_type': 'url'}
            url_analysis = UrlAnalysis.from_analysis_id(analysis_id)
            if wait_for_completion:
                url_analysis.wait_for_completion()
        except IntezerError as e:
            phantom.save_progress(f'Get url report failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Get url report failed - {e}')
        if url_analysis.status != AnalysisStatusCode.FINISHED:
            self.intezer_action_result.add_data(
                {**base_summary, 'analysis_status': url_analysis.status.value, 'analysis_content': {}})
            self.intezer_action_result.update_summary(
                {**base_summary, 'analysis_status': url_analysis.status.value, 'analysis_content': {}})
            phantom.save_progress('Url analysis is still running')
            return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

        result = {**base_summary,
                  'analysis_status': AnalysisStatusCode.FINISHED.value,
                  'analysis_content': {'analysis': url_analysis.result()}}
        self.intezer_action_result.add_data(result)
        self.intezer_action_result.update_summary(result)
        phantom.save_progress('Url analysis finished')
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def get_alert(self, alert_id: str, wait_for_completion: bool = True, **kwargs):
        """
        Get an alert analyze information.

        :param alert_id: The alert id to get.
        :param wait_for_completion: Whether to wait for the analysis to finish.
        """
        phantom.save_progress('Getting alert')
        try:
            alert = Alert.from_id(alert_id, wait=wait_for_completion)
            alert_details = alert.result()
        except IntezerError as e:
            phantom.save_progress(f'Get alert failed - {e}')
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Get alert failed - {e}')
        self.intezer_action_result.add_data(alert_details)
        self.intezer_action_result.update_summary(alert_details)
        phantom.save_progress('Alert finished')
        return self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def initialize(self, **kwargs):
        # get the asset config
        try:
            config = self.get_config()
        except Exception:
            return phantom.APP_ERROR
        self._intezer_api_key = config[INTEZER_JSON_APIKEY]
        set_global_api(self._intezer_api_key)
        self.api = get_global_api()
        return phantom.APP_SUCCESS

    def handle_action(self, param, **kwargs):
        """Run relevant action according to given action id."""
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.intezer_action_result = self.add_action_result(ActionResult(dict(param)))
        if action_id not in self.action_mapper:
            return self.intezer_action_result.set_status(phantom.APP_ERROR, f'Unknown action {action_id}')
        return self.action_mapper[action_id](**param)

    def _locate_file_path(self, vault_id: str):
        try:
            _, _, file_info = ph_rules.vault_info(vault_id=vault_id)
            if not file_info:
                return self.intezer_action_result.set_status(phantom.APP_ERROR, 'Could not retrieve vault file')
            file_info = list(file_info)[0]

            file_path = file_info['path']
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            if 'List index out of range' in error_message:
                return self.intezer_action_result.set_status(phantom.APP_ERROR,
                                                             'Unable to retrieve file from vault. Invalid vault_id.')
            else:
                return self.intezer_action_result.set_status(phantom.APP_ERROR,
                                                             f'Unable to retrieve file from vault: {error_message}')
        return file_path, self.intezer_action_result.set_status(phantom.APP_SUCCESS)

    def _get_temp_path(self, file_hash):
        # Create a tmp directory on the vault partition

        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'

        local_dir = f'{temp_dir}/{guid}'
        self.save_progress(f'Using temp directory: {guid}')
        os.makedirs(local_dir)

        return f'{local_dir}/{file_hash}'

    def _save_file_to_vault(self, action_result, file_path, file_hash):
        contains = []
        file_ext = ''

        file_name = f'{file_hash}{file_ext}'

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_location=file_path,
                                              container_id=self.get_container_id(),
                                              file_name=file_name)

        current_data = {}

        if vault_ret_dict['succeeded']:
            current_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            current_data[phantom.APP_JSON_NAME] = file_name
            if contains:
                current_data['file_type'] = ','.join(contains)
            action_result.add_data(current_data)
            action_result.update_summary(current_data)
            action_result.set_status(phantom.APP_SUCCESS,
                                     f'File successfully retrieved and added to vault - vault_id = {vault_ret_dict[phantom.APP_JSON_HASH]}')
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        local_dir = '/'.join(file_path.split('/')[:-1])
        try:
            shutil.rmtree(local_dir)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(f'Unable to remove temporary directory {local_dir} - {e}')

        return action_result.get_status()


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass('Password: ')

    if username and password:
        try:
            login_url = BaseConnector._get_phantom_base_url() + 'login'

            print('Accessing the Login page')
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print('Logging into Platform to get the session id')
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print('Unable to get session id from the platform. Error: ' + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IntezerConnector()
        connector.initialize()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector.handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)

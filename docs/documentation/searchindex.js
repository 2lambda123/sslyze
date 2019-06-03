Search.setIndex({docnames:["available-scan-commands","index","running-scan-commands","testing-connectivity","writing-a-plugin"],envversion:{"sphinx.domains.c":1,"sphinx.domains.changeset":1,"sphinx.domains.citation":1,"sphinx.domains.cpp":1,"sphinx.domains.javascript":1,"sphinx.domains.math":2,"sphinx.domains.python":1,"sphinx.domains.rst":1,"sphinx.domains.std":1,sphinx:56},filenames:["available-scan-commands.rst","index.rst","running-scan-commands.rst","testing-connectivity.rst","writing-a-plugin.rst"],objects:{"nassl.ssl_client":{OpenSslFileTypeEnum:[3,1,1,""]},"nassl.ssl_client.OpenSslFileTypeEnum":{ASN1:[3,2,1,""],PEM:[3,2,1,""]},"sslyze.concurrent_scanner":{ConcurrentScanner:[2,1,1,""],PluginRaisedExceptionScanResult:[2,1,1,""]},"sslyze.concurrent_scanner.ConcurrentScanner":{__init__:[2,3,1,""],get_results:[2,3,1,""],queue_scan_command:[2,3,1,""]},"sslyze.concurrent_scanner.PluginRaisedExceptionScanResult":{error_message:[2,2,1,""]},"sslyze.plugins":{certificate_info_plugin:[0,0,0,"-"],compression_plugin:[0,0,0,"-"],early_data_plugin:[0,0,0,"-"],fallback_scsv_plugin:[0,0,0,"-"],heartbleed_plugin:[0,0,0,"-"],http_headers_plugin:[0,0,0,"-"],openssl_ccs_injection_plugin:[0,0,0,"-"],openssl_cipher_suites_plugin:[0,0,0,"-"],plugin_base:[0,0,0,"-"],robot_plugin:[0,0,0,"-"],session_renegotiation_plugin:[0,0,0,"-"],session_resumption_plugin:[0,0,0,"-"]},"sslyze.plugins.certificate_info_plugin":{CertificateChainDeploymentAnalysisResult:[0,1,1,""],CertificateChainDeploymentAnalyzer:[0,1,1,""],CertificateInfoScanCommand:[0,1,1,""],CertificateInfoScanResult:[0,1,1,""],OcspResponseStatusEnum:[0,1,1,""],PathValidationError:[0,1,1,""],PathValidationResult:[0,1,1,""],SymantecDistrustTimelineEnum:[0,1,1,""]},"sslyze.plugins.certificate_info_plugin.CertificateChainDeploymentAnalyzer":{perform:[0,3,1,""]},"sslyze.plugins.certificate_info_plugin.CertificateInfoScanCommand":{__init__:[0,3,1,""]},"sslyze.plugins.certificate_info_plugin.CertificateInfoScanResult":{leaf_certificate_has_must_staple_extension:[0,2,1,""],leaf_certificate_is_ev:[0,2,1,""],leaf_certificate_signed_certificate_timestamps_count:[0,2,1,""],leaf_certificate_subject_matches_hostname:[0,2,1,""],ocsp_response:[0,2,1,""],ocsp_response_is_trusted:[0,2,1,""],ocsp_response_status:[0,2,1,""],path_validation_error_list:[0,2,1,""],path_validation_result_list:[0,2,1,""],received_certificate_chain:[0,2,1,""],received_chain_contains_anchor_certificate:[0,2,1,""],received_chain_has_valid_order:[0,2,1,""],verified_certificate_chain:[0,2,1,""],verified_chain_has_legacy_symantec_anchor:[0,2,1,""],verified_chain_has_sha1_signature:[0,2,1,""]},"sslyze.plugins.certificate_info_plugin.OcspResponseStatusEnum":{INTERNAL_ERROR:[0,2,1,""],MALFORMED_REQUEST:[0,2,1,""],SIG_REQUIRED:[0,2,1,""],SUCCESSFUL:[0,2,1,""],TRY_LATER:[0,2,1,""],UNAUTHORIZED:[0,2,1,""]},"sslyze.plugins.certificate_info_plugin.PathValidationError":{error_message:[0,2,1,""],trust_store:[0,2,1,""]},"sslyze.plugins.certificate_info_plugin.PathValidationResult":{trust_store:[0,2,1,""],verified_certificate_chain:[0,2,1,""],verify_string:[0,2,1,""],was_validation_successful:[0,2,1,""]},"sslyze.plugins.certificate_info_plugin.SymantecDistrustTimelineEnum":{MARCH_2018:[0,2,1,""],SEPTEMBER_2018:[0,2,1,""]},"sslyze.plugins.compression_plugin":{CompressionScanCommand:[0,1,1,""],CompressionScanResult:[0,1,1,""]},"sslyze.plugins.compression_plugin.CompressionScanResult":{compression_name:[0,2,1,""]},"sslyze.plugins.early_data_plugin":{EarlyDataScanCommand:[0,1,1,""],EarlyDataScanResult:[0,1,1,""]},"sslyze.plugins.early_data_plugin.EarlyDataScanResult":{is_early_data_supported:[0,2,1,""]},"sslyze.plugins.fallback_scsv_plugin":{FallbackScsvScanCommand:[0,1,1,""],FallbackScsvScanResult:[0,1,1,""]},"sslyze.plugins.fallback_scsv_plugin.FallbackScsvScanResult":{supports_fallback_scsv:[0,2,1,""]},"sslyze.plugins.heartbleed_plugin":{HeartbleedScanCommand:[0,1,1,""],HeartbleedScanResult:[0,1,1,""]},"sslyze.plugins.heartbleed_plugin.HeartbleedScanResult":{is_vulnerable_to_heartbleed:[0,2,1,""]},"sslyze.plugins.http_headers_plugin":{HttpHeadersScanCommand:[0,1,1,""],HttpHeadersScanResult:[0,1,1,""]},"sslyze.plugins.http_headers_plugin.HttpHeadersScanResult":{expect_ct_header:[0,2,1,""],is_backup_pin_configured:[0,2,1,""],is_valid_pin_configured:[0,2,1,""],public_key_pins_header:[0,2,1,""],public_key_pins_report_only_header:[0,2,1,""],strict_transport_security_header:[0,2,1,""],verified_certificate_chain:[0,2,1,""]},"sslyze.plugins.openssl_ccs_injection_plugin":{OpenSslCcsInjectionScanCommand:[0,1,1,""],OpenSslCcsInjectionScanResult:[0,1,1,""]},"sslyze.plugins.openssl_ccs_injection_plugin.OpenSslCcsInjectionScanResult":{is_vulnerable_to_ccs_injection:[0,2,1,""]},"sslyze.plugins.openssl_cipher_suites_plugin":{AcceptedCipherSuite:[0,1,1,""],CipherSuiteScanResult:[0,1,1,""],ErroredCipherSuite:[0,1,1,""],RejectedCipherSuite:[0,1,1,""],Sslv20ScanCommand:[0,1,1,""],Sslv30ScanCommand:[0,1,1,""],Tlsv10ScanCommand:[0,1,1,""],Tlsv11ScanCommand:[0,1,1,""],Tlsv12ScanCommand:[0,1,1,""],Tlsv13ScanCommand:[0,1,1,""]},"sslyze.plugins.openssl_cipher_suites_plugin.AcceptedCipherSuite":{is_anonymous:[0,2,1,""],key_size:[0,2,1,""],name:[0,2,1,""],openssl_name:[0,2,1,""],post_handshake_response:[0,2,1,""],ssl_version:[0,2,1,""]},"sslyze.plugins.openssl_cipher_suites_plugin.CipherSuiteScanResult":{accepted_cipher_list:[0,2,1,""],errored_cipher_list:[0,2,1,""],preferred_cipher:[0,2,1,""],rejected_cipher_list:[0,2,1,""]},"sslyze.plugins.openssl_cipher_suites_plugin.ErroredCipherSuite":{error_message:[0,2,1,""],is_anonymous:[0,2,1,""],name:[0,2,1,""],openssl_name:[0,2,1,""],ssl_version:[0,2,1,""]},"sslyze.plugins.openssl_cipher_suites_plugin.RejectedCipherSuite":{handshake_error_message:[0,2,1,""],is_anonymous:[0,2,1,""],name:[0,2,1,""],openssl_name:[0,2,1,""],ssl_version:[0,2,1,""]},"sslyze.plugins.plugin_base":{Plugin:[4,1,1,""],PluginScanCommand:[4,1,1,""],PluginScanResult:[0,1,1,""]},"sslyze.plugins.plugin_base.Plugin":{process_task:[4,3,1,""]},"sslyze.plugins.plugin_base.PluginScanCommand":{__init__:[4,3,1,""],get_cli_argument:[4,3,1,""],is_aggressive:[4,3,1,""]},"sslyze.plugins.plugin_base.PluginScanResult":{scan_command:[0,2,1,""],server_info:[0,2,1,""]},"sslyze.plugins.robot_plugin":{RobotScanCommand:[0,1,1,""],RobotScanResult:[0,1,1,""],RobotScanResultEnum:[0,1,1,""]},"sslyze.plugins.robot_plugin.RobotScanResult":{robot_result_enum:[0,2,1,""]},"sslyze.plugins.robot_plugin.RobotScanResultEnum":{NOT_VULNERABLE_NO_ORACLE:[0,2,1,""],NOT_VULNERABLE_RSA_NOT_SUPPORTED:[0,2,1,""],UNKNOWN_INCONSISTENT_RESULTS:[0,2,1,""],VULNERABLE_STRONG_ORACLE:[0,2,1,""],VULNERABLE_WEAK_ORACLE:[0,2,1,""]},"sslyze.plugins.session_renegotiation_plugin":{SessionRenegotiationScanCommand:[0,1,1,""],SessionRenegotiationScanResult:[0,1,1,""]},"sslyze.plugins.session_renegotiation_plugin.SessionRenegotiationScanResult":{accepts_client_renegotiation:[0,2,1,""],supports_secure_renegotiation:[0,2,1,""]},"sslyze.plugins.session_resumption_plugin":{SessionResumptionRateScanCommand:[0,1,1,""],SessionResumptionRateScanResult:[0,1,1,""],SessionResumptionSupportScanCommand:[0,1,1,""],SessionResumptionSupportScanResult:[0,1,1,""]},"sslyze.plugins.session_resumption_plugin.SessionResumptionRateScanResult":{attempted_resumptions_nb:[0,2,1,""],errored_resumptions_list:[0,2,1,""],failed_resumptions_nb:[0,2,1,""],successful_resumptions_nb:[0,2,1,""]},"sslyze.plugins.session_resumption_plugin.SessionResumptionSupportScanResult":{attempted_resumptions_nb:[0,2,1,""],errored_resumptions_list:[0,2,1,""],failed_resumptions_nb:[0,2,1,""],is_ticket_resumption_supported:[0,2,1,""],successful_resumptions_nb:[0,2,1,""],ticket_resumption_exception:[0,2,1,""],ticket_resumption_failed_reason:[0,2,1,""]},"sslyze.plugins.utils.trust_store":{trust_store:[0,0,0,"-"],trust_store_repository:[0,0,0,"-"]},"sslyze.plugins.utils.trust_store.trust_store":{TrustStore:[0,1,1,""]},"sslyze.plugins.utils.trust_store.trust_store.TrustStore":{name:[0,2,1,""],path:[0,2,1,""],version:[0,2,1,""]},"sslyze.plugins.utils.trust_store.trust_store_repository":{TrustStoresRepository:[0,1,1,""]},"sslyze.plugins.utils.trust_store.trust_store_repository.TrustStoresRepository":{update_default:[0,3,1,""]},"sslyze.server_connectivity_info":{ServerConnectivityInfo:[3,1,1,""]},"sslyze.server_connectivity_info.ServerConnectivityInfo":{client_auth_credentials:[3,2,1,""],client_auth_requirement:[3,2,1,""],get_preconfigured_ssl_connection:[3,3,1,""],highest_ssl_version_supported:[3,2,1,""],hostname:[3,2,1,""],http_tunneling_settings:[3,2,1,""],ip_address:[3,2,1,""],openssl_cipher_string_supported:[3,2,1,""],port:[3,2,1,""],tls_server_name_indication:[3,2,1,""],tls_wrapped_protocol:[3,2,1,""],xmpp_to_hostname:[3,2,1,""]},"sslyze.server_connectivity_tester":{ConnectionToServerTimedOut:[3,1,1,""],ProxyConnectivityError:[3,1,1,""],ServerConnectivityError:[3,1,1,""],ServerConnectivityTester:[3,1,1,""],ServerHostnameCouldNotBeResolved:[3,1,1,""],ServerRejectedConnection:[3,1,1,""],ServerTlsConfigurationNotSuportedError:[3,1,1,""]},"sslyze.server_connectivity_tester.ServerConnectivityError":{error_message:[3,2,1,""],server_info:[3,2,1,""]},"sslyze.server_connectivity_tester.ServerConnectivityTester":{__init__:[3,3,1,""],perform:[3,3,1,""]},"sslyze.ssl_settings":{ClientAuthenticationCredentials:[3,1,1,""],HttpConnectTunnelingSettings:[3,1,1,""],TlsWrappedProtocolEnum:[3,1,1,""]},"sslyze.ssl_settings.ClientAuthenticationCredentials":{__init__:[3,3,1,""]},"sslyze.ssl_settings.HttpConnectTunnelingSettings":{__init__:[3,3,1,""]},"sslyze.ssl_settings.TlsWrappedProtocolEnum":{HTTPS:[3,2,1,""],PLAIN_TLS:[3,2,1,""],STARTTLS_FTP:[3,2,1,""],STARTTLS_IMAP:[3,2,1,""],STARTTLS_LDAP:[3,2,1,""],STARTTLS_POP3:[3,2,1,""],STARTTLS_POSTGRES:[3,2,1,""],STARTTLS_RDP:[3,2,1,""],STARTTLS_SMTP:[3,2,1,""],STARTTLS_XMPP:[3,2,1,""],STARTTLS_XMPP_SERVER:[3,2,1,""]},"sslyze.synchronous_scanner":{SynchronousScanner:[2,1,1,""]},"sslyze.synchronous_scanner.SynchronousScanner":{__init__:[2,3,1,""],run_scan_command:[2,3,1,""]},nassl:{ssl_client:[3,0,0,"-"]},sslyze:{concurrent_scanner:[2,0,0,"-"],server_connectivity_info:[3,0,0,"-"],server_connectivity_tester:[3,0,0,"-"],ssl_settings:[3,0,0,"-"],synchronous_scanner:[2,0,0,"-"]}},objnames:{"0":["py","module","Python module"],"1":["py","class","Python class"],"2":["py","attribute","Python attribute"],"3":["py","method","Python method"]},objtypes:{"0":"py:module","1":"py:class","2":"py:attribute","3":"py:method"},terms:{"abstract":[0,4],"class":1,"default":[0,3],"enum":0,"function":0,"int":[0,2,3],"long":0,"new":[1,2,4],"public":[0,1],"return":[0,2,3,4],"true":[0,4],"try":[0,1,2,3],"while":[0,2,3],CCS:0,DNS:3,DOS:[2,4],For:[0,4],IDs:0,NOT:0,Such:3,TLS:[0,1,2,3],The:[0,1,4],Then:2,Used:3,Useful:0,Using:1,Will:0,__init__:[0,2,3,4],abl:[0,3],about:[2,3],abov:3,accept:0,accepted_cipher_list:[0,1,2],acceptedciphersuit:0,accepts_client_renegoti:0,access:[1,2],accord:0,accur:4,achiev:3,across:1,act:0,actual:3,add:1,added:4,addit:[1,3],address:3,advanc:1,after:[0,3],against:[0,1,3,4],aggress:4,algorithm:0,all:[0,1,2,3],allow:3,also:[0,2,3],alwai:0,among:0,analysi:0,analyz:[0,1],anchor:0,android:0,ani:[0,1],anonym:0,appendix:[1,2],appl:0,argument:[3,4],as_text:4,as_xml:4,asn1:3,assum:3,attack:0,attempt:[0,3],attempted_resum_nb:0,attempted_resumptions_nb:0,attribut:[1,2,3],authent:[0,1],avail:2,avoid:[2,4],back:0,bad:1,base:0,basic:1,basic_auth_password:3,basic_auth_us:3,been:2,befor:[2,3],being:2,below:0,bit:0,bleichenbach:0,block:[0,2],blog:0,bool:[0,4],both:[0,3],bug:2,built:[0,1],c0d3:0,ca_fil:0,call:[2,3],can:[0,1,2,3,4],cannot:[2,3],capabl:1,cert:2,cert_common_nam:2,certif:[0,1,2,3],certificate_info_plugin:0,certificatechaindeploymentanalysisresult:0,certificatechaindeploymentanalyz:0,certificateinfoplugin:1,certificateinfoscancommand:[0,2],certificateinfoscanresult:0,chain:[0,2],chanc:2,check:0,cipher:[0,1,2,3],ciphersuitescancommand:0,ciphersuitescanresult:0,cippher:0,classmethod:[0,4],classs:3,cli:4,client:[0,1],client_auth_credenti:3,client_auth_requir:3,client_certificate_chain_path:3,client_key_password:3,client_key_path:3,client_key_typ:3,clientauthenticationcredenti:3,clientauthenticationserverconfigurationenum:3,close:0,com:[0,1,2,3],comand:1,command:4,common:2,common_nam:2,complet:[0,2,3],complex:2,compress:0,compression_nam:0,compression_plugin:[0,4],compressionplugin:[1,4],compressionscancommand:0,compressionscanresult:0,comput:0,concurr:[1,4],concurrent_scann:2,concurrentscann:[1,3,4],configur:[0,1,3],connect:[1,2,4],connectiontoservertimedout:3,consol:4,constant:3,constructor:3,contain:[0,2,3],continu:1,control:3,core:1,correspond:[0,2,4],could:[0,1,2,3],creat:[2,4],cryptographi:0,current:0,custom:0,cve:0,danger:1,data:0,date:0,decrypt:3,def:[1,2,3],demo_concurrent_scann:2,demo_server_connectivity_test:[2,3],demo_synchronous_scann:[1,2],depend:2,deploi:0,deprec:0,describ:[0,1,2,3],detail:2,detect:[1,3],determin:0,dict:0,did:0,directli:3,discov:4,dispatch:2,displai:4,distrust:0,document:[0,1,2],doe:0,doing:3,downgrad:0,download:0,dure:0,each:[0,2],earli:0,early_data_plugin:0,earlydataplugin:1,earlydatascancommand:0,earlydatascanresult:0,easi:1,easiest:4,either:2,element:[0,4],elif:2,els:2,embed:0,empti:0,enabl:1,encapsul:3,endpoint:1,engin:1,ensur:[2,3],enumer:0,error:[0,2,3],error_messag:[0,1,2,3],errored_cipher_list:0,errored_resumptions_list:0,erroredciphersuit:0,essenti:0,establish:[1,2,3],estim:0,etc:[0,1,2,3],ev_oid:0,everi:[0,2],exampl:[0,1],except:[0,1,2,3],exist:[0,4],exot:3,expect:[0,3],expect_ct_head:0,expectcthead:0,explain:[0,2],explicitli:0,extend:0,extens:[0,3],fail:[0,2,3],failed_resumptions_nb:0,fallback_scsv_plugin:0,fallbackscsvplugin:1,fallbackscsvscancommand:0,fallbackscsvscanresult:0,fals:0,fast:2,faster:2,feasibl:0,figur:3,file:[0,3],find:3,fine:3,first:2,follow:[0,1],format:[0,2,3],found:0,from:0,full:[1,3],gener:3,get:[3,4],get_attributes_for_oid:2,get_cli_argu:4,get_preconfigured_ssl_connect:3,get_result:2,get_titl:2,github:0,give:1,given:[0,3],gmail:[1,2,3],googl:0,grain:3,handshak:[0,3],handshake_error_messag:0,happen:[0,3],has:[2,3],have:[0,2],header:0,heartble:0,heartbleed_plugin:0,heartbleedplugin:1,heartbleedscancommand:0,heartbleedscanresult:0,hello:3,help:4,helper:1,here:4,hide_rejected_ciph:0,high:1,highest:3,highest_ssl_version_support:3,honor:0,hostnam:[1,2,3],how:[1,2,3],hpkp:0,hpkp_pin:0,hst:0,http:[0,3],http_get:0,http_headers_plugin:0,http_tunneling_set:3,httpconnecttunnelingset:3,httpheadersscancommand:0,httpheadersscanplugin:1,httpheadersscanresult:0,human:0,identifi:3,implement:[0,1,4],includ:0,index:[0,1],indic:3,inform:[2,3],ing:[2,4],initi:[0,2,3,4],inject:0,instal:0,instanc:[2,3],instanti:3,instead:2,intermedi:0,intern:1,internal_error:0,ip_address:3,is_aggress:4,is_anonym:0,is_backup_pin_configur:0,is_early_data_support:0,is_ticket_resumption_support:0,is_valid_pin_configur:0,is_vulnerable_to_ccs_inject:0,is_vulnerable_to_heartble:0,isinst:2,issu:[0,1],iter:2,java:0,kei:[0,3],key_siz:0,keyword:4,kind:[2,3],lack:1,larg:2,last:0,later:2,latest:0,leaf:0,leaf_certificate_has_must_staple_extens:0,leaf_certificate_is_ev:0,leaf_certificate_signed_certificate_timestamps_count:0,leaf_certificate_subject_matches_hostnam:0,least:[0,3],level:1,like:3,line:4,list:[0,1,2,3,4],listen:3,look:[0,2,3],lookup:3,lot:2,lower:2,made:4,make:1,malformed_request:0,mani:[2,4],map:3,march_2018:0,max_processes_nb:2,max_processes_per_hostname_nb:2,maximum:2,mean:2,mechan:[0,2],messag:[0,3],method:[2,3],microsoft:0,misconfigur:1,modul:[0,1,2],more:[2,3],most:3,mozilla:0,much:2,multipl:[2,4],must:[2,3],mutual:3,nabla:0,name:[0,1,2,3],nameoid:2,nassl:[0,3],need:[2,3,4],network:3,network_retri:2,network_timeout:[2,3],never:[0,3],next:3,nich:3,non:3,none:[0,2,3,4],nonetyp:0,not_vulnerable_no_oracl:0,not_vulnerable_rsa_not_support:0,nprocess:2,nqueu:2,nreceiv:2,ntest:[1,2,3],number:[0,2,3],object:[0,2,3],occur:2,ocsp:0,ocsp_respons:0,ocsp_response_is_trust:0,ocsp_response_statu:0,ocspresponsestatusenum:0,offlin:3,old:0,onc:2,one:[0,1,2,3,4],ongo:2,onli:[0,3,4],onlin:[2,3],open:4,openssl:[0,3],openssl_ccs_injection_plugin:0,openssl_cipher_string_support:3,openssl_cipher_suites_plugin:0,openssl_nam:0,opensslccsinjectionplugin:1,opensslccsinjectionscancommand:0,opensslccsinjectionscanresult:0,opensslciphersuitesplugin:1,opensslfiletypeenum:3,opensslversionenum:[0,3],option:[0,3,4],oracl:0,order:[0,3],other:1,out:[2,3],output:4,override_ssl_vers:3,own:1,packag:0,page:[0,1],paramet:[0,2,3,4],parent:1,pars:0,part:1,pass:[3,4],password:3,path:[0,3],path_validation_error_list:0,path_validation_result_list:0,pathvalidationerror:0,pathvalidationresult:0,pem:[0,3],per:4,perform:[0,1,2,3,4],pin:0,plain_tl:3,platform:1,plugin:[0,1,3],plugin_bas:[0,4],plugin_repositori:4,pluginraisedexceptionresult:2,pluginraisedexceptionscanresult:2,pluginscancommand:[0,2,4],pluginscanresult:[0,2,4],pool:2,port:[1,2,3],post_handshake_respons:0,prefer:0,preferred_ciph:0,prevent:0,previous:2,print:[1,2,3],privat:3,process:[1,2],process_task:4,properli:2,protocol:1,provid:[0,3],proxi:1,proxyconnectivityerror:3,public_key_pins_head:0,public_key_pins_report_only_head:0,publickeypinshead:0,publickeypinsreportonlyhead:0,quali:0,queu:2,queue:2,queue_scan_command:2,rais:[0,1,2,3],rang:1,rate:0,reach:3,reachabl:[2,3],readabl:0,real:0,receiv:4,received_certificate_chain:0,received_chain:0,received_chain_contains_anchor_certif:0,received_chain_has_valid_ord:0,received_ocsp_respons:0,reduc:2,refer:0,regard:3,reject:[0,3],rejected_cipher_list:0,rejectedciphersuit:0,releas:[0,1],renegoti:[0,2],report:0,repository_path:0,repres:[0,2,4],request:0,requir:3,respons:[0,3],result:[0,2,4],resumpt:[0,1],retri:2,retriev:[0,2],review:4,rfc:0,right:3,robot:0,robot_plugin:0,robot_result_enum:0,robotplugin:1,robotscancommand:0,robotscanresult:0,robotscanresultenum:0,root:0,rsa:0,run:[0,1,4],run_scan_command:[1,2],runtimeerror:[1,2,3],same:2,scan:4,scan_command:[0,2,4],scan_result:[1,2],scancommand:[0,2],scanner:2,scanresult:[0,2],sct:0,search:1,second:3,section:[0,1],secur:[0,1],see:4,self:4,send:[0,3],sent:0,september_2018:0,sequenti:1,server:[0,1,4],server_connectivity_info:3,server_connectivity_test:3,server_hostnam:0,server_info:[0,1,2,3,4],server_test:[1,2,3],serverconnectivityerror:[1,2,3],serverconnectivityinfo:[0,1,2,4],serverconnectivitytest:[1,2],serverhostnamecouldnotberesolv:3,serverrejectedconnect:3,servertlsconfigurationnotsuportederror:3,session:[0,1,2],session_renegotiation_plugin:0,session_resumption_plugin:0,sessionrenegotiationplugin:1,sessionrenegotiationscancommand:0,sessionrenegotiationscanresult:0,sessionresumptionplugin:1,sessionresumptionratescancommand:0,sessionresumptionratescanresult:0,sessionresumptionsupportscancommand:0,sessionresumptionsupportscanresult:0,set:[0,3],setup:2,sever:[2,3],sha:0,share:1,shortcut:0,should:[0,2,3,4],should_use_legacy_openssl:3,sig_requir:0,sign:0,signatur:4,simpl:[1,4],simultan:4,singl:2,size:0,slightli:2,small:3,smtp:[1,2,3],socket:3,some:2,spawn:2,specif:[0,2,3,4],specifi:3,ssl:[0,1,2,3],ssl_client:3,ssl_filetype_xxx:3,ssl_set:3,ssl_verify_loc:3,ssl_version:0,sslconnect:3,ssllab:0,sslv20scancommand:0,sslv30scancommand:0,sslyze:[0,2,3,4],standard:3,stapl:0,start:[3,4],starttl:1,starttls_ftp:3,starttls_imap:3,starttls_ldap:3,starttls_pop3:3,starttls_postgr:3,starttls_rdp:3,starttls_smtp:[1,2,3],starttls_xmpp:3,starttls_xmpp_serv:3,statu:0,step:1,store:1,str:[0,2,3,4],stream:3,strict:0,strict_transport_security_head:0,stricttransportsecurityhead:0,string:[0,3],subclass:[2,4],subject:2,success:[0,3],successful_resum_nb:0,successful_resumptions_nb:0,successfulli:3,suit:[0,1,2,3],suppli:[0,3,4],support:[0,1,2],supports_fallback_scsv:0,supports_secure_renegoti:0,symantec:0,symantecdistrusttimelineenum:0,synchron:2,synchronous_scann:[1,2],synchronousscann:[1,3],system:[0,1,4],take:0,target:2,test:[0,1,2],test_connectivity_to_serv:2,tester:3,text:[0,2,4],than:2,thei:2,them:2,thi:[0,1,2,3],thing:4,threat:0,threw:2,through:1,ticket:0,ticket_resumption_except:0,ticket_resumption_failed_reason:0,time:[2,3],timeout:3,timestamp:0,tls_fallback_scsv:0,tls_server_name_ind:3,tls_wrapped_protocol:[0,1,2,3],tlsv10scancommand:[0,1,2],tlsv11scancommand:0,tlsv12scancommand:[0,2],tlsv13scancommand:0,tlswrappedprotocolenum:[0,1,2,3],too:0,tool:[1,4],total:0,traffic:3,transpar:0,transport:0,trigger:0,trust:[1,2],trust_stor:0,trust_store_repositori:0,trust_store_used_to_build_verified_chain:0,trust_stores_observatori:0,truststor:0,truststoresrepositori:0,try_lat:0,tunnel:3,two:[0,1],type:[0,2,3,4],unabl:3,unauthor:0,underli:3,unexpect:[0,2],union:0,unknown_inconsistent_result:0,unless:3,until:2,updat:1,update_default:0,usag:1,use:[0,2,3],used:[0,2,3,4],usernam:3,uses:[2,3],using:[0,1,2,3,4],util:0,valid:0,valu:[2,3],valueerror:3,variou:[0,1],veri:[2,3],verifi:[0,2],verified_certificate_chain:[0,2],verified_chain:0,verified_chain_has_legacy_symantec_anchor:0,verified_chain_has_sha1_signatur:0,verify_str:0,version:[0,3],via:4,vulner:0,vulnerable_strong_oracl:0,vulnerable_weak_oracl:0,wai:4,want:4,was_validation_success:0,were:[0,3],what:[2,3],when:[0,2,3,4],whether:[0,3],which:[0,1,2,3,4],why:0,within:[0,2,3],without:[0,3],would:0,wrap:3,write:1,x509:0,xml:4,xml_out:4,xmpp:3,xmpp_to_hostnam:3,you:4,your:1,zlib:0},titles:["Appendix: Available Scan Commands","SSLyze Python API","Step 2: Running Scan Commands Against a Server","Step 1: Testing Connectivity to a Server","Appendix: Writing Your Own Plugins"],titleterms:{"class":[0,2,3,4],The:[2,3],addit:0,advanc:3,against:2,api:1,appendix:[0,4],attribut:0,authent:3,avail:[0,1],basic:[2,3],certificateinfoplugin:0,client:3,command:[0,1,2,3],compressionplugin:0,concurr:2,concurrentscann:2,connect:3,core:4,earlydataplugin:0,enabl:3,exampl:[2,3],extend:1,fallbackscsvplugin:0,guid:1,heartbleedplugin:0,helper:0,high:4,httpheadersscanplugin:0,indic:1,level:4,opensslccsinjectionplugin:0,opensslciphersuitesplugin:0,other:3,overview:[1,4],own:4,parent:4,plugin:4,protocol:3,proxi:3,python:1,robotplugin:0,run:[2,3],scan:[0,1,2,3],sequenti:2,server:[2,3],serverconnectivityinfo:3,serverconnectivitytest:3,sessionrenegotiationplugin:0,sessionresumptionplugin:0,share:0,sslyze:1,starttl:3,step:[2,3],store:0,support:3,synchronousscann:2,tabl:1,test:3,through:3,trust:0,updat:0,usag:3,user:1,write:4,your:4}})
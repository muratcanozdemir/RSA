function rsa_convert_privat_to_public_key(email_address)
%** this removes the outfile_priv_code from the key_identifier file. It does not delete the coded key file itself!!!
if nargin<1 || isempty(email_address),
   email_address=' ';
end;
email_address=strtrim(lower(email_address));


dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;


matfile=[dirn,'\key_identifiers.mat'];
if exist(matfile,'file')~=2,
   error('key_identifier file not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
end;

keyID=[];
default_privID=[];
load(matfile,'keyID','default_privID');
i=-1;
for k=1:size(keyID,1),
   if strcmp(keyID{k,1},email_address),
      i=k;
      break;
   end;
end;
if i<0,
   error('%s not found in key_identifier file',email_address);
end;
if isempty(keyID{i,3}),
   warndlg(sprintf('Key %s is already a public key. No changes will be made!',email_address),'!! Info !!');
   return;
end;
if strcmp(default_privID,email_address),
   warndlg(sprintf('The default privat key %s has been converted in a public key. To reestablish the default privat key run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!',email_address),'!! Info !!');
   %return;
   default_privID=[];
end;
keyID{i,3}='';
save(matfile,'keyID','default_privID');
end

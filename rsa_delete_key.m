function rsa_delete_key(email_address)
%this deletes the entire line of email_address in the key_identifier file. It does not delete the coded key files itself!!!

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
if strcmp(default_privID,email_address),
   default_privID=[];
   warndlg(sprintf('The default privat key %s has been deleted in the key_identifier file. To reestablish the default privat key run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!',email_address),'!! Info !!');
end;

if size(keyID,1)<2,
   delete(matfile);
   return;
end;
keyID=keyID(setdiff(1:size(keyID,1),i),:);
save(matfile,'keyID','default_privID');
end

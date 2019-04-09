function rsa_generate_key_files(my_email_address)
% generates a pair of public and private keys and stores them in two different file:
%  The public key in: 
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',my_email_address,'.pub.code']
%  The private and the public key in:
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',my_email_address,'.priv.code']
%  The email_address and the corresponding filenames of these codes are also stored in 
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\key_identifiers.mat']
%  DO NOT ALLOW ANYBODY EXCEPT YOURSELF ACCESS TO THIS DIRECTORY FOR SECURITY REASONS !!!!!!!
if nargin<1 || isempty(my_email_address),
   my_email_address=' ';
end;
my_email_address=strtrim(lower(my_email_address));
if isempty(my_email_address),
   error('my_email_adress is empty!!!');
end;

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

default_privID=[];
replace_default_privID=true;
warn_for_PrivatKeyUpdate=true;

matfile=[dirn,'\key_identifiers.mat'];
if exist(matfile,'file')==2,
   keyID=[];
   default_privID=[];
   load(matfile,'keyID','default_privID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},my_email_address),
         i=k;
         break;
      end;
   end;
   if i>0,
      resp=questdlg(sprintf('%s found in key_identifier file! Do you want to overwrite the content?',my_email_address),' ','Yes','No','No');
      if isempty(resp) || strcmp(resp,'No');
         return;
      end;
   end;
   if  ~strcmp(my_email_address,default_privID) && ~isempty(default_privID),
      resp=questdlg(sprintf('Your present default private key is %s. Do you want to change it to %s ?',default_privID,my_email_address),' ','Yes','No','No');
      replace_default_privID=(~isempty(resp) && ~strcmp(resp,'No'));
   end;
   if strcmp(my_email_address,default_privID),
      replace_default_privID=false;
   end;
end;


[n,e,d]=rsa_generate_key();


outfile=[dirn,'\',my_email_address,'.pub'];
fid=fopen(outfile,'wt');
fprintf(fid,'%s\n',my_email_address);
fprintf(fid,'%d\n%d\n',n,e);
fclose(fid);

outfile_pub_code=rsa_code(outfile,1);
delete(outfile);
%rsa_code(outfile_pub_code,-1,[],[],'return')

outfile=[dirn,'\',my_email_address,'.priv'];
fid=fopen(outfile,'wt');
fprintf(fid,'%s\n',my_email_address);
fprintf(fid,'%d\n%d\n%d\n',n,e,d);
fclose(fid);

outfile_priv_code=rsa_code(outfile,1);
delete(outfile);
%rsa_code(outfile_priv_code,-1,[],[],'return')


[fp,fn,fe]=fileparts(outfile_priv_code);
outfile_priv_code=[fn,fe];
[fp,fn,fe]=fileparts(outfile_pub_code);
outfile_pub_code=[fn,fe];

if exist(matfile,'file')~=2,
   keyID={my_email_address,outfile_pub_code,outfile_priv_code};
else
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},my_email_address),
         i=k;
         break;
      end;
   end;
   if i<0,
      i=size(keyID,1)+1;
   end;
   keyID{i,1}=my_email_address;
   keyID{i,2}=outfile_pub_code;
   keyID{i,3}=outfile_priv_code;
end;
if replace_default_privID,
   if isempty(default_privID),
      warndlg(sprintf('Default privat key has been set to %s',my_email_address),'!! Info !!')
   else
      warndlg(sprintf('Old default privat key %s has been modified to %s',default_privID,my_email_address),'!! Info !!')
   end;
   default_privID=my_email_address;
end;
if warn_for_PrivatKeyUpdate,
   warndlg(sprintf('Privat key has been modified. Remember to send %s to all who want to send mails to %s!',outfile_pub_code,my_email_address),'!! Info !!')
end;
save(matfile,'keyID','default_privID');
end
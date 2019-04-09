function res=rsa_encode_email(filename,recipient_email_address)
if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(recipient_email_address),
   recipient_email_address=' ';
end;


recipient_email_address=strtrim(lower(recipient_email_address));
if isempty(recipient_email_address),
   error('recipient_email_address is empty!!!');
end;


filename=strtrim(filename);
if exist(filename,'file')~=2,
   error(sprintf('%s does not exist!',filename));
end;

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

%** retrieve public key of recipient:
matfile=[dirn,'\key_identifiers.mat'];
if exist(matfile,'file')~=2,
   error('key_identifier file not found. For creating a new one, run rsa_import_key(address.pub.code)!');
end;
keyID=[];
load(matfile,'keyID');
i=-1;
for k=1:size(keyID,1),
   if strcmp(keyID{k,1},recipient_email_address),
      i=k;
      break;
   end;
end;
if i<0,
   error(sprintf('%s not found in key_identifier file. Check spelling or run rsa_import_key(address.pub.code)!',recipient_email_address));
end;

outfile_pub_code=[dirn,filesep,keyID{i,2}];

outf_decode=rsa_code(outfile_pub_code,-1);
fid=fopen(outf_decode,'rt');
adr=fscanf(fid,'%s\n',1);
n=fscanf(fid,'%d\n',1);
e=fscanf(fid,'%d\n',1);
fclose(fid);
delete(outf_decode);

res=rsa_code(filename,n,e,'encode');
if nargout<1,
   warndlg(sprintf('Encoded file written to %s .',res),'!! Info !!')
end;

end



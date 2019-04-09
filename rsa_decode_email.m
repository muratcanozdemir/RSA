function res=rsa_decode_email(filename,outfile,my_email_address)
%res=rsa_decode_email(filename,outfile,my_email_address)
%  filename: name of coded file
%   outfile: where to place the output:  'return': output to command line  (default)
%                                          'auto':aut generated filename
% my_email address: private key identifier used for decoding.
%                     default: default private key as stored in the key_identifier file
if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(outfile),
   outfile='return';
end;
if nargin<3 || isempty(my_email_address),
   my_email_address=' ';
end;

if strcmp(strtrim(lower(outfile)),'auto'),
   outfile='';
end;
outfile=strtrim(lower(outfile));


filename=strtrim(filename);
if exist(filename,'file')~=2,
   error(sprintf('%s does not exist!',filename));
end;

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;


matfile=[dirn,'\key_identifiers.mat'];
if exist(matfile,'file')~=2,
   error('key_identifier file not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
end;


my_email_address=strtrim(lower(my_email_address));
if isempty(my_email_address),
   default_privID=[];
   load(matfile,'default_privID');
   if isempty(default_privID),
      error('default_privID not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
   end;
   my_email_address=default_privID;
end;


%** retrieve my private key:
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
   error('%s not found in key_identifier file. Check spelling or run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!',my_email_address);
end;

if isempty(keyID{i,3}),
   error('The privat key of %s is not known!',my_email_address);
end;
outfile_priv_code=[dirn,filesep,keyID{i,3}];

outf_decode=rsa_code(outfile_priv_code,-1);
fid=fopen(outf_decode,'rt');
adr=fscanf(fid,'%s\n',1);
n=fscanf(fid,'%d\n',1);
e=fscanf(fid,'%d\n',1);
d=fscanf(fid,'%d\n',1);
fclose(fid);
delete(outf_decode);

res=rsa_code(filename,n,d,'decode',outfile);
if nargout<1 && ~strcmp(outfile,'return'),
   warndlg(sprintf('Decoded file written to %s .',res),'!! Info !!')
end;

end



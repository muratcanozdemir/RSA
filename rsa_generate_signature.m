function outname=rsa_generate_signature(n,d,e,dat)
%public: n,e
%privat: n,d
%   use both public and private key to create a signature
%   call type 1:  rsa_generate_signature();
%                   uses the default privat key.priv.code file and creates a signature that expires after 5 days
%                 rsa_generate_signature([],dat);  with ~isempty(dat)
%                   uses the default privat key.priv.code file and creates a signature that expires to date
%   call type 2:  rsa_generate_signature(my_email_address[,dat]);
%                   uses the specified privat key.priv.code file and creates a signature that expires acording to date
%   call type 3:  rsa_generate_signature([]  [,[],[],dat]  );
%                   uses the default numeric keys and creates a signature that expires acording to dat
%   call type 4:  rsa_generate_signature(n,d,e[,dat]);
%                   uses the key numbers and creates a signature that expires acording to date
%        
%
% dat: NaN:      code without specified date (this signatures never expire)
%      'today':  code with actual date       (default)
%      [yyyy,mm,dd]: date vector
%      'dd.mm.yyyy': date string
% Return value:
% outname: the name of the generated signature file

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

if nargin<1 || (nargin==2 && isempty(n) && ~isempty(d))  ...  % call type 1 
      || (ischar(n) && ~isempty(n)) ,                         % or call type 2
   
   
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
   end;
   if nargin<2,  % default settings for call type 1 or call type 2
      d='today';
   end;
else
   adr='NaN';
   if nargin<4 || isempty(dat),   % default settings for call type 3 and 4
      dat='today';  %try to decode with actual date
   end;
end;




if nargin<1 || (nargin==2 && isempty(n) && ~isempty(d)),  % call type 1 : modify this call into a call type 2
   default_privID=[];
   load(matfile,'default_privID');
   if isempty(default_privID),
      error('default_privID not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
   end;
   my_email_address=default_privID;
   n=my_email_address;
end;

if ischar(n) && ~isempty(n),  % call type 2 : modify into call type 4:
   dat=d;
   my_email_address=n;
   my_email_address=strtrim(lower(my_email_address));
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
end;




%***  call type 3 and 4
if isempty(n),
   e=1434425;
   d=2033849;
   n=2868847; 
end;



if ~isnan(dat),
   if ischar(dat),
      if strcmp(strtrim(lower(dat)),'today'),
         dat=round(datenum(date));
      else
         dat=round(datenum(dat,'dd.mm.yyyy'));
      end;
   else
      dat=round(datenum(dat));
   end;
end;

filename=[dirn,'\rsa_signature.txt'];

fid=fopen(filename,'wt');
if isnan(dat),
   fprintf(fid,'%d\n',0);
   fprintf(fid,'%s\n',adr);
   fprintf(fid,'%d\n%d\n',n,e);
else
   fprintf(fid,'%d\n',dat);
   fprintf(fid,'%s\n',adr);
   rand('seed',dat);
   r=floor(rand(10,1)*10000);
   for k=1:10,
      fprintf(fid,'%d\n',r(k));
   end;
   fprintf(fid,'%d\n%d\n',n,e);
   r=floor(rand(10,1)*10000);
   for k=1:10,
      fprintf(fid,'%d\n',r(k));
   end;
end;
fclose(fid);

outname=rsa_code(filename,n,d);
%*** write the address identifier at the beginning of the coded file
fid=fopen(outname,'rb');
ds=fread(fid);
ds=char(ds)';
fclose(fid);
%** add a string at the beginning, terminated by 10 *****
ds=['___RSA_SIGNATURE___',adr,char(10),ds];
fid=fopen(outname,'wb');
fwrite(fid,ds,'char');
fclose(fid);
%********************************************************




delete(filename);

if nargout<1,
   warndlg(sprintf('signature file written to %s .',outname),'!! Info !!')
end;
   
end


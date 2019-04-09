function signature_correct=rsa_check_signature(filename,n,e)
%checks a signature generated with rsa_generate_signature
% call type 1: rsa_check_signature(filename)
%               uses the email address written in the signature to retrieve the public key via the key_identifier file
% call type 2: rsa_check_signature(filename,n,e)
%               uses numeric keys entered in n,e 
% call type 3: rsa_check_signature(filename,[])
%               uses default numeric keys entered in n,e 

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn)~=7,
   mkdir(dirn);
end;

if exist(filename,'file')~=2,
   error('$s does not exist!',filename);
end;

%** try to retrieve the address string from the beginning of the file: ***
fid=fopen(filename,'rt');
adr=fscanf(fid,['___RSA_SIGNATURE___%s',char(10)],1);
dstart_p=ftell(fid);
fclose(fid);

if isempty(adr),
   error('%s is not a signature file!',filename);
end;

if nargin<2,  % call type 1: convert to call type 2
   if strcmp(adr,'NaN'),
      error('The signature file %s was not created using rsa_generate_signature() or rsa_generate_signature(my_email_address[,dat]) !!',filename);
   end;
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!');
   end;
   
   pub_email_address=adr;
   pub_email_address=strtrim(lower(pub_email_address));
   
%** retrieve my private key:
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},pub_email_address),
         i=k;
         break;
      end;
   end;
   if i<0,
      error('%s not found in key_identifier file. Check spelling or run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!',pub_email_address);
   end;
   
   outfile_pub_code=[dirn,filesep,keyID{i,2}];
   
   outf_decode=rsa_code(outfile_pub_code,-1);
   fid=fopen(outf_decode,'rt');
   adr_1=fscanf(fid,'%s\n',1);
   n=fscanf(fid,'%d\n',1);
   e=fscanf(fid,'%d\n',1);
   fclose(fid);
   delete(outf_decode);
end;


if isempty(n),
   e=1434425;  %** this [n,e] is the default public key
   n=2868847; 
end;

rsa_code(filename,n,e,'decode','',dstart_p);



[fp,fn,fe]=fileparts(filename);
outname=[fn,fe];
outname=[dirn,'\',outname,'.decode'];

fid=fopen(outname,'rt');
numdat=fscanf(fid,'%d\n',1);
adr=fscanf(fid,'%s\n',1);
nums=fscanf(fid,'%d\n');
fclose(fid);
delete(outname);

if isempty(nums),
   warning('rsa_check_signature:DecodeFailure','signature can not be decoded with this key!');
   signature_correct=false;
   return;
end;
if numdat==0,  %** signature is coded without date
   if length(nums)<2,
      warning('rsa_check_signature:DecodeFailure','signature can not be decoded with this key!');
      signature_correct=false;
      return;
   end;
   signature_correct=(n==nums(1) && e==nums(2));
else
   dat=numdat;
   if length(nums)<22,
      warning('rsa_check_signature:DecodeFailure','signature can not be decoded with this key!');
      signature_correct=false;
      return;
   end;
   signature_correct=true;
   if ischar(dat),
      if strcmp('today',strtrim(lower(dat))),
         rand('seed',round(datenum(date)));
      else
         rand('seed',round(datenum(dat,'dd.mm.yyyy')));
      end;
   else
      rand('seed',round(datenum(dat)));
   end;
   r=floor(rand(10,1)*10000);
   j=0;
   for k=1:10,
      j=j+1;
      if nums(j)~=r(k),
         signature_correct=false;
         break;
      end;
   end;
   if signature_correct,
      signature_correct=(n==nums(j+1) && e==nums(j+2));
      j=j+2;
      if signature_correct,
         r=floor(rand(10,1)*10000);
         for k=1:10,
            j=j+1;
            if nums(j)~=r(k),
               signature_correct=false;
               break;
            end;
         end;
      end;
   end;
   dat1=round(datenum(date));
   if signature_correct && dat<dat1-5,
      wm=sprintf('signature created on %s is out of date!',datestr(dat,'dd.mm.yyyy'));
      warning('rsa_check_signature:OutOfDate',wm);
      signature_correct=-1;
   end;

end;


end


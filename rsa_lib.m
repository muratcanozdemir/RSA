function rsal=rsa_lib()
if isempty(which('XXXInt_subtract'))
   myaddpath('matc');
end;
%*** high level functions: ***
rsal.generate_key_files=@generate_key_files;      % generate_key_files(key_name[,bit_length])
rsal.encode_data=@encode_data;                    % res=encode_data(filename,key_name)
rsal.decode_data=@decode_data;                    % res=decode_data(filename,outfile,key_name)
rsal.sign_data=@sign_data;                        % res=sign_data(filename,outfile,key_name)
rsal.check_signed_data=@check_signed_data;        % [isvalid,check]=check_signed_data(filename,signature_file,key_name)
rsal.manage_key=@manage_key;                      % manage_key()
rsal.import_key=@import_key;                      % import_key([filename_code])
rsal.export_pub_from_priv_code=@export_pub_from_priv_code; %export_pub_from_priv_code(priv_code_filename)

%*** low level functions: ***
rsal.read_txt_keyfile=@read_txt_keyfile;  %key=read_txt_keyfile(keyfilename,do_print)
rsal.chr_decode=@chr_decode;  %DECODE1=chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus)
rsal.isequal_byte_sequence=@isequal_byte_sequence; % ise=isequal_byte_sequence(X1,X2)
rsal.RsaCoder=@RsaCoder;                             %res=RsaCoder(filename,key,action,outname,start_ptr)

rsal.generate_key=@generate_key;                     %key_txt=generate_key([bit_length)
rsal.write_txt_key=@write_txt_key;                   %write_txt_key(fid,priv_key_txt,pub_only)
end

%rsa_key_text is a public key generated with
      %cd c:\Program Files (x86)\Apache Software Foundation\Apache2.4\bin
      %set RANDFILE=.rnd
      %openssl req -newkey rsa:384 -out test.csr
      %openssl rsa -text -noout -in privkey.pem
function key=read_txt_keyfile(keyfilename,do_print)
   key=struct('bit_length',NaN ...
             ,'publicExponent',[] ...
             ,'modulus',[] ...
             ,'exponent1',[] ...
             ,'exponent2',[] ...
             ,'privateExponent',[] ...
             ,'coefficient',[] ...
             ,'prime1',[] ...
             ,'prime2',[] ...
             ,'m_package_byte_length',NaN ...
             );
   if nargin<2 || isempty(do_print),
      do_print=false;
   end;
   
   if size(keyfilename,1)>1,
      rsa_key_text=keyfilename;
   else
      rsa_key_text=t_read(keyfilename,10);
   end;
   
      is_PrivKeyFile=true;
      keyword='Private-Key';
      i=0;
      while i<size(rsa_key_text,1)
         i=i+1;
         [t,hstr]=strtok(rsa_key_text(i,:),':');
         if strcmp(t,keyword),
            break;
         end;
      end
      if ~strcmp(t,keyword),
         keyword='Public-Key';
         i=0;
         while i<size(rsa_key_text,1)
            i=i+1;
            [t,hstr]=strtok(rsa_key_text(i,:),':');
            if strcmp(t,keyword),
               break;
            end;
         end
         if ~strcmp(t,keyword),
            error('File is not a text key file!');
         end;
         is_PrivKeyFile=false;
      end;
      hstr=strtrim(hstr(2:end));
      hstr=hstr(2:end-1);
      [t,hstr]=strtok(hstr,' ');
      hstr=strtrim(hstr(2:end));
      if ~strcmp(hstr,'bit'),
         error('Key length is not given in bit!');
      end;
      bit_length=eval(t);
      
      keyword='publicExponent';
      i=0;
      while i<size(rsa_key_text,1)
         i=i+1;
         [t,hstr]=strtok(rsa_key_text(i,:),':');
         if strcmp(t,keyword),
            break;
         end;
      end
      if ~strcmp(t,keyword),
         error('%s not found!!',keyword);
      end;
      hstr=strtrim(hstr(2:end));
      [t,hstr]=strtok(hstr(1:end-1),'(');
      [t,hstr]=strtok(hstr(1:end),'(');
      if ~strcmp(t(1:2),'0x'),
         error('Hexindicator is missing!');
      end;
      t=strtrim(t(3:end));
      if mod(length(t),2)~=0,
         t=['0',t];
      end;
      NBytes=round(length(t)/2);
      publicExponent=uint8(zeros(1,NBytes));
      for k=1:NBytes,
         publicExponent(k)=uint8(hex2dec(t(2*(k-1)+(1:2))));
      end;
      if publicExponent(1)>127,
         publicExponent=[uint8(0),publicExponent];
      end;
      
      
      
      byte_length=round(bit_length/8);
      keyword='modulus';
      modulus=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(modulus);
      end;
      if modulus(1)>127,
         modulus=[uint8(0),modulus];
      end;
      j=find(modulus~=0,1,'first');
      if isempty(j),
         error('modulus is zero!');
      end;
      m_package_byte_length=length(modulus)-j;
      
      
      if ~is_PrivKeyFile,
         key.bit_length=bit_length;
         key.publicExponent=publicExponent;
         key.modulus=modulus;
         key.m_package_byte_length=m_package_byte_length;
         return;
      end;
      
      byte_length=round(bit_length/16);
      keyword='exponent1';
      exponent1=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(exponent1);
      end;
      if exponent1(1)>127,
         exponent1=[uint8(0),exponent1];
      end;
      
      byte_length=round(bit_length/16);
      keyword='exponent2';
      exponent2=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(exponent2);
      end;
      if exponent2(1)>127,
         exponent2=[uint8(0),exponent2];
      end;
      
      byte_length=round(bit_length/8);
      keyword='privateExponent';
      privateExponent=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(privateExponent);
      end;
      if privateExponent(1)>127,
         privateExponent=[uint8(0),privateExponent];
      end;
      
      
      byte_length=round(bit_length/16);
      keyword='coefficient';
      coefficient=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(coefficient);
      end;
      if coefficient(1)>127,
         coefficient=[uint8(0),coefficient];
      end;
      
      byte_length=round(bit_length/16);
      keyword='prime1';
      prime1=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(prime1);
      end;
      if prime1(1)>127,
         prime1=[uint8(0),prime1];
      end;
      
      byte_length=round(bit_length/16);
      keyword='prime2';
      prime2=read_byte_sequence(rsa_key_text,keyword,byte_length);
      if do_print,
         fprintf('%s:\n',keyword);
         printf_byte_sequence(prime2);
      end;
      if prime2(1)>127,
         prime2=[uint8(0),prime2];
      end;
      
      prod=XXXInt_prod(prime1,prime2);
      if do_print,
         fprintf('%s:\n','prime1*prime2');
         printf_byte_sequence(prod);
      end;
      if ~isequal_byte_sequence(prod,modulus),
         fprintf('prime1*prime2 ~= modulus\n');
         error('read_txt_keyfile');
      end;
      
      
      X1=XXXInt_subtract(prime1,uint8(1));
      [Q,R]=XXXInt_divide(privateExponent,X1);
      if ~isequal_byte_sequence(R,exponent1),
         fprintf('exponent1~=privateExponent mod (prime1-1)\n');
         error('read_txt_keyfile');
      end;
      
      X1=XXXInt_subtract(prime2,uint8(1));
      [Q,R]=XXXInt_divide(privateExponent,X1);
      if ~isequal_byte_sequence(R,exponent2),
         fprintf('exponent2~=privateExponent mod (prime2-1)\n');
         error('read_txt_keyfile');
      end;
      
      
      prod=XXXInt_prod(coefficient,prime2);
      [Q,I]=XXXInt_divide(prod,prime1);
      
      if ~isequal_byte_sequence(I,uint8(1)),
         fprintf('coefficient*prime2 mod prime1 ~= 1\n');
         error('read_txt_keyfile');
      end;
      
      key.bit_length=bit_length;
      key.publicExponent=publicExponent;
      key.modulus=modulus;
      key.m_package_byte_length=m_package_byte_length;
      
      key.exponent1=exponent1;
      key.exponent2=exponent2;
      key.privateExponent=privateExponent;
      key.coefficient=coefficient;
      key.prime1=prime1;
      key.prime2=prime2;

end


function DECODE1=chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus)
%** rsa decoding using chinese remainder theorem
   C1=XXXInt_pow_mod(CODE,exponent1,prime1);
   C2=XXXInt_pow_mod(CODE,exponent2,prime2);
%    if isequal_byte_sequence(C1,C2),
%       fprintf('C1==C2\n');
%    end;
   while isbigger_byte_sequence(C2,C1),
      C1=XXXInt_add(C1,prime1);
   end;
   CDIFF=XXXInt_subtract(C1,C2);
   CPROD=XXXInt_prod(coefficient,CDIFF);
   [Q,CPROD]=XXXInt_divide(CPROD,prime1);
   CPROD=XXXInt_prod(CPROD,prime2);
   DECODE1=XXXInt_add(CPROD,C2);
   [Q,DECODE1]=XXXInt_divide(DECODE1,modulus);
end


function ise=isequal_byte_sequence(X1,X2)
x1_null=all(X1==0);
x2_null=all(X2==0);
if x1_null || x2_null,
   if (x1_null && ~x2_null) || (~x1_null && x2_null),
      ise=false;
   else
      ise=true;
   end;
   return;
end;

X1=X1(find(X1>0,1,'first'):end);
X2=X2(find(X2>0,1,'first'):end);
if length(X1)~=length(X2),
   ise=false;
   return;
end;

ise=all(X1==X2);
end

function isb=isbigger_byte_sequence(X1,X2)
x1_null=all(X1==0);
x2_null=all(X2==0);
if x1_null || x2_null,
   if x1_null && ~x2_null,
      isb=false;
   elseif ~x1_null && x2_null,
      isb=true;
   else
      isb=false;
   end;
   return;
end;

X1=X1(find(X1>0,1,'first'):end);
X2=X2(find(X2>0,1,'first'):end);
l1=length(X1);
l2=length(X2);
if l1~=l2,
   if l1>l2,
      isb=true;
   else
      isb=false;
   end;
   return;
end;

isb=false;
for k=1:l1,
   if X1(k)~=X2(k),
      isb=(X1(k)>X2(k));
      break;
   end;
end;
end

function write_byte_sequence(fid,seq,keyword)
%** write the byte sequense to an open text file:
byte_length=length(seq);
fprintf(fid,'%s:%c',keyword,10);
i=0;
while i<byte_length,
   ie=min(i+15,byte_length);
   fprintf(fid,'    ');
   for k=i+1:ie,
      bs=lower(dec2hex(seq(k)));
      if length(bs)<2,
         bs=['0',bs];
      end;
      fprintf(fid,'%s',bs);
      if k<byte_length,
         fprintf(fid,':');
      end;
   end
   fprintf(fid,'%c',10);
   i=ie;
end;
end

function modulus=read_byte_sequence(rsa_key_text,keyword,byte_length)
i=0;
while i<size(rsa_key_text,1)
   i=i+1;
   [t,hstr]=strtok(rsa_key_text(i,:),':');
   if strcmp(t,keyword),
      break;
   end;
end
if ~strcmp(t,keyword),
   error('%s not found!!',keyword);
end;

last_remainder=':';
byte_count=0;
modulus=uint8(zeros(1,byte_length+1));
while ~isempty(last_remainder),
   i=i+1;
   hstr=rsa_key_text(i,:);
   while ~isempty(hstr),
      [t,hstr]=strtok(hstr,':');
      t=strtrim(t);
      if isempty(t),
         continue;
      end;
      last_remainder=hstr;
      if length(t)~=2,
         error('invalid byte string');
      end;
      byte_count=byte_count+1;
      if byte_count>byte_length+1,
         error('number of bytes too large!!');
      end;
      modulus(byte_count)=hex2dec(t);
   end;
end;
modulus=modulus((1:byte_length)+byte_count-byte_length);
end

function printf_byte_sequence(modulus)
str='';
byte_length=length(modulus);
for k=1:byte_length,
   hstr=dec2hex(modulus(k));
   if length(hstr)<2,
      hstr=['0',hstr];
   end;
   str=[str,hstr];
   if k<byte_length,
      str=[str,':'];
   end;
   if mod(k-1,15)==14,
      fprintf('%s\n',str);
      str='';
   end;
end;
if mod(byte_length-1,15)<14,
   fprintf('%s\n',str);
end;
end

function key=default_key()
      rsa_key_text=strvcat(...
         'Private-Key: (384 bit)' ...
         ,'modulus:' ...
         ,'    00:a9:f7:24:b6:2e:1d:51:8e:4b:90:b4:8d:34:e8:' ...
         ,'    12:b4:dd:6b:2e:45:f9:cb:15:38:77:24:10:e4:94:' ...
         ,'    75:7d:c1:cd:65:9c:8c:5e:ac:b7:78:e7:1d:81:30:' ...
         ,'    a3:cf:a1:29' ...
         ,'publicExponent: 65537 (0x10001)' ...
         ,'privateExponent:' ...
         ,'    44:3e:fb:5b:b7:7a:88:43:d5:ad:be:01:b1:0b:ba:' ...
         ,'    6f:2b:35:1d:38:75:cb:88:b2:23:08:cb:00:4b:1e:' ...
         ,'    2b:0b:82:0a:bb:e2:c2:19:0a:5c:9a:0f:9d:c6:8b:' ...
         ,'    b1:70:2d' ...
         ,'prime1:' ...
         ,'    00:d0:fc:e9:7d:5c:95:e8:51:2b:48:d9:ae:f5:86:' ...
         ,'    5f:1f:be:5e:42:69:de:c2:14:eb' ...
         ,'prime2:' ...
         ,'    00:d0:33:05:a7:a8:45:02:63:e8:65:9b:7a:df:7f:' ...
         ,'    15:05:b2:2f:ad:3a:da:56:ad:3b' ...
         ,'exponent1:' ...
         ,'    00:b0:ae:80:ff:98:fc:ab:71:a3:f4:6d:04:bb:52:' ...
         ,'    24:ad:83:95:d0:f4:0c:7d:6c:8d' ...
         ,'exponent2:' ...
         ,'    4a:37:85:f2:88:17:61:8c:bf:d1:48:a5:7a:7a:50:' ...
         ,'    c2:21:0c:c1:d1:d2:f7:46:f5' ...
         ,'coefficient:' ...
         ,'    00:ab:4d:e8:4f:6b:32:3a:e4:80:aa:0e:69:b3:a3:' ...
         ,'    92:83:e7:8a:9b:18:0b:ed:e4:5d');
      
   key=read_txt_keyfile(rsa_key_text);
end

function res=RsaCoder(filename,key,action,modus,outname,start_ptr)
%*** this is a symmetric version of rsa_code_asym
%***  filename: input filename
%***         n: basis
%***         E: exponent
%***    action:    'decode': do decoding
%***               'encode': do encoding using a random "salt" (default)
%***            'encode_NS': do encoding without salt 
%***     modus: 0: encoding with public key, decoding with private key (default)
%***            1: encoding with private key, decoding with public key
%***   outname: 'return': the encoded or decoded data are returned in res and no file is written.
%***                  '': name of the output file is automatically generated and returned in res.  (default)
%***            string s: otherwise,  the string s determines the filename of the output file
%***                     (Path component is irrelevant). The output filename is 
%***                     [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',s,'.code'] for encoding, and 
%***                     [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',s,'.decode'] for decoding.
%***                     The resulting filename is returned in res.
%*** start_ptr: byte pointer pointing to the first character of the data block.  (default: 0)
%***  
%***
%*** Returned variable
%*** outname:   name of the output file or the result
%*** call 1:
%***     RsaCoder(filename,1)  % encoding with default public numeric key 
%*** call 2:
%***     RsaCoder(filename,-1)  % decoding with default privat numeric key 

if nargin<2 || isempty(key),
   mask='*.code';
   title_str='Load Key-File:';
   eval(['[filename_code, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(filename_code,0)| isequal(filename_code,0),
      return;
   end;
   filename_code=[pathname,filename_code];
   if isempty(filename_code),
      res=[];
      return;
   end;
   outf_decode=RsaCoder(filename_code,-1,'decode',1);
   key=read_txt_keyfile(outf_decode,false);
   delete(outf_decode);

end;
if nargin<3 || isempty(action),
   action='encode';
   default_action=true;
else
   default_action=false;
end;
if nargin<4 || isempty(modus),
   modus=0;
end;
if nargin<5 || isempty(outname),
   outname='';
end;
if nargin<6 || isempty(start_ptr),
   start_ptr=0;
end;
action=strtrim(lower(action));
if strcmp(action,'decode'),     %** decoding with or without salt
   code_type=0;    
elseif strcmp(action,'encode'),     %** encoding with salt
   code_type=2;
else
   code_type=1;                     %** encoding without salt
end;
write_to_file=~strcmp('return',strtrim(lower(outname)));

if ~isstruct(key) && abs(key)==1,
   if key==1,
      if default_action,        %***** overwrite default action if abs(n)==1
         code_type=1;      %** encoding without salt
      end;
   else
      if default_action,
         code_type=0;         %** decoding with or without salt
      end;
   end;
   key=default_key();
end;
if ~isempty(outname) && write_to_file,
   [fp,fn,fe]=fileparts(outname);
   outname=[fn,fe];
elseif write_to_file,
   [fp,fn,fe]=fileparts(filename);
   outname=[fn,fe];
end;
if write_to_file,
   dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
   if exist(dirn,'dir')~=7,
      mkdir(dirn);
   end;
end;
if code_type>0,
   if write_to_file,
      outname=[dirn,'\',outname,'.code'];
   end;
   if code_type==2,
      salt=floor(rand(1,1)*1e7-1.0);
   else
      salt=-1;
   end;
   res=encode_file(filename,outname,key,start_ptr,salt,modus);
   if write_to_file && code_type==2,
      fid=fopen(outname,'r');
      data=fread(fid);
      fclose(fid);
      
      salt_s=sprintf('**_SALT:_%7d_***',salt);
      ind=strfind(salt_s,' ');
      salt_s(ind)='_';
      fid=fopen(outname,'wt');
      fprintf(fid,'%s\n',salt_s);
      fclose(fid);
      fid=fopen(outname,'a');
      fwrite(fid,data,'uint8');
      fclose(fid);      
   end;
else
   if write_to_file,
      outname=[dirn,'\',outname,'.decode'];
   end;
   %** check whether code is salted: *********
   fid=fopen(filename,'rt');
   fseek(fid,start_ptr,'bof');
   cont=true;
   while cont,
      salt_s=fscanf(fid,'%s\n',1);
      cont=(length(salt_s)<1);
   end;
   cnt=ftell(fid);
   fclose(fid);
   is_salted=length(salt_s)>19 && strcmp(salt_s(1:9),'**_SALT:_');
   if is_salted,
      tmp_s=salt_s(10:16);  %** SALT: 1234567 ***
      salt_d=double(tmp_s);
      tmp=(salt_d>47 & salt_d<58);
      tmp_da=salt_d(tmp);
      
      l_salt=length(tmp_da);
      is_salted=(is_salted && l_salt>0);
      if is_salted,
         tmp_d=cnt;
         start_ptr=tmp_d;
         salt=tmp_da(l_salt)-48;
         salt_f=1;
         if l_salt>1,
            for k=2:l_salt,
               salt_f=salt_f*10;
               salt=salt+(tmp_da(l_salt-k+1)-48)*salt_f;
            end;
         end;
      else
         salt=-1;
      end;
   else
      salt=-1;
   end;
      
   res_d=decode_file(filename,outname,key,start_ptr,salt,modus);
   if ~write_to_file,  %*** decoding on the commandline without writing to disk changes dos format to UNIX format
      %***  binary originals are not necessarily returned correctly!!!!! ********
      res_d(res_d>127)=127;
      res=char(res_d);
      ind=strfind(res,char([13 10]));
      if isempty(ind)==0,
         res=res(setdiff((1:length(res)),ind));
      end;
   end;
end;
if write_to_file,
   res=outname;
end;
end


function y=mod_power(m,e,n);
% p=m;
% for i=1:e-1,
%    p=mod(p*m,n);
% end;

y=m;
if length(e)==1,
   bi=binary_convert(e,2,32);
   sti=find(bi>0,1,'first');
   ste=32;
else
   bi=e;
   sti=1;
   ste=length(bi);
end;
for i=sti+1:ste,
   y=mod(y*y,n);
   if bi(i)>0,
      y=mod(y*m,n);
   end;
end;

end

function bi=binary_convert(x,base,ndigits)
%convert a  positive scalar value to an array of length ndigits each between 0 and (base-1)
% highest significant: bi(1) 
x=double(x);
if x==0,
   bi=0;
else
   bi=[];
end;
while x>0,
   bi=[mod(x,base),bi];
   x=floor(x/base);
end;
if length(bi)>ndigits,
   error('Number too large for binary conversion!');
end;
if length(bi)<ndigits,
   z=zeros(1,ndigits-length(bi));
   bi=[z,bi];
end;
end


function x=binary_reconvert(bi,base)
x=0;
f=1;
L=length(bi);
for i=0:L-1,
   x=x+double(bi(L-i))*f;
   f=f*base;
end;
end

function ds=n_bit_coding(d,m,n,salt)
%d: uint vector with m bit resolution
% ds: coded vector with n bit resolution (returned as double vector)
% for n<7, ds returns a character matrix
d=double(d);
c=uint8(zeros(length(d),m));
mod_term=round(2^m);
for i=1:length(d),
   if salt>=0,
      d(i)=mod(d(i)+salt,mod_term);
   end;
   c(i,:)=binary_convert(d(i),2,m);
   c(i,:)=c(i,m:-1:1);
end;
c=c';
c=c(:);
k=ceil(length(c)/n);
cs=uint8(zeros(k*n,1));
cs(1:length(c))=c;
cs=reshape(cs,n,k);
cs=cs';
ds=zeros(k,1);
for i=1:k,
   ds(i)=binary_reconvert(cs(i,n:-1:1),2);
end;

end



function cv=convert_double_to_char_vector(ds,linelength)
% returns a character matrix
   codes=[(48:57),(97:122),(65:90),43,45];
   k=ceil(length(ds)/linelength);
   dc=zeros(k*linelength,1);
   dc(1:length(ds))=codes(ds+1);
   dc=reshape(dc,linelength,k)';
   if k*linelength>length(ds),
      dc(k,linelength-k*linelength+length(ds)+1:linelength)=32;
   end;
   cv=char(dc);
end


function dd=convert_char_to_double_vector(d_)

d=d_;
   codes=[(48:57),(97:122),(65:90),43,45];
   d=d(:)';
   
   ind_=strfind(d,char([13 10]));
   ind=ind_';
   tmp_d=isempty(ind);
   if tmp_d==0,
      ind_=union(ind,ind+1,'rows');
      ind_row=ind_(:)';
      ind_=setdiff((1:length(d)),ind_row);
      ind=ind_;
      d=d(ind);
   end;
   ind=strfind(d,char(10));
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind(1,:)));
   end;
   ind=strfind(d,char(13));
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind(1,:)));
   end;
   ind=strfind(d,' ');
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind(1,:)));
   end;
   ind=strfind(d,char(9));
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind(1,:)));
   end;
   dd=double(d);
   for i=1:length(d),
      dd(i)=find(codes==dd(i),1,'first')-1;
   end;
end



function ds=n_bit_decoding(d,n,m,salt)
d=double(d(:));


c=uint8(zeros(length(d),n));
for i=1:length(d),
   c(i,:)=binary_convert(d(i),2,n);
   c(i,:)=c(i,n:-1:1);
end;
c=c';
c=c(:);
ind=find(c>0,1,'last');
c=c(1:ind);
k=ceil(length(c)/m);
cs=uint8(zeros(k*m,1));
cs(1:length(c))=c;
cs=reshape(cs,m,k);
cs=cs';
ds=zeros(k,1);
mod_term=round(2^m);
for i=1:k,
   ds(i)=binary_reconvert(cs(i,m:-1:1),2);
   if salt>=0,
      ds(i)=mod(ds(i)-salt,mod_term);
   end;
end;
end


function o=filter_coding(data,modulus,salt)
n=double(modulus(length(modulus)))+double(modulus(length(modulus)-1));
if salt>=0,
   e=salt+1;
   n=round(mod(n+salt,10000000));
else
   e=83458399;
end;
[a,b]=mk_filtpars(n,e);
o=z_filter(b,a,data);
end

function o=filter_decoding(data,modulus,salt)
n=double(modulus(length(modulus)))+double(modulus(length(modulus)-1));
if salt>=0,
   e=salt+1;
   n=round(mod(n+salt,10000000));
else
   e=83458399;
end;
[a,b]=mk_filtpars(n,e);
o=z_filter(a,b,data);
end

function [a,b]=mk_filtpars(n,e)
pa=blowup_n(n,e,3);
phi=[ 0,   0,  20,  -20,  80, -80, 180,  180;
     40, -40, 120, -120,  70, -70, 150, -150]*pi/180;
pa=repmat(pa(:)',2,1);
pa=pa(:);
r=reshape(pa,2,8)*0.19/round(2^16)+0.8;
ab=zeros(2,9);
for j=1:2,
   a=1;
   for k=1:4,
      phi1=phi(j,2*(k-1)+1);
      phi2=phi(j,2*k);
      if phi1==phi2,
         p=r(j,2*k)*cos(phi1);
         a=conv(a,[1 p]);
         a=conv(a,[1 p]);
      else
         p=r(j,2*k)*(cos(phi1)+i*sin(phi1));
         a=conv(a,[1 p]);
         p=r(j,2*k)*(cos(phi2)+i*sin(phi2));
         a=conv(a,[1 p]);
      end;
   end;
   ab(j,:)=a;
end;
a=real(ab(1,:));
b=real(ab(2,:));
end

function a=blowup_n(n,e,p2)
xs=n;
x=mod(xs,round(2^16));
for k=1:p2,
   xs=n_bit_coding(x,16,8,-1)+2^5;

   for i=1:length(xs),
      xs(i)=mod_power(xs(i),e,n);
   end;
   x=mod(xs,round(2^16));
end;
a=x;
end




function y=z_filter(b,a,x);
if size(x,1)>1 & size(x,2)>0
   y=[];
   for k=1:size(x,2),
      y=[y,filter(b,a,x(:,k))];
   end;
   return;
end;
         
La=length(a);
Lb=length(b);
b=b/a(1);
a=a/a(1);
a=a(:)';
a=a(La:-1:1);
b=b(:)';
b=b(Lb:-1:1);
si=size(x);
x=x(:);
N=length(x);
y=zeros(N+La-1,1);
x=[zeros(Lb-1,1);x];
for i=1:N,
   y(i+La-1)=b*x(i:i+Lb-1)-a(1:La-1)*y(i:i+La-2);
end;
y=y(La:La+N-1);
y=reshape(y,si(1),si(2));
end




function res=decode_file(filename,outname,key,start_ptr,salt,modus)
write_to_file=~strcmp('return',strtrim(lower(outname)));
if ~write_to_file,
   dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
   if exist(dirn,'dir')~=7,
      mkdir(dirn);
   end;
   outname=[dirn,'\tmptmp.decode'];
end;

fid=fopen(filename,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid);
fseek(fid,start_ptr,'bof');
data=fread(fid);
ds=char(data);
fclose(fid);

data=convert_char_to_double_vector(ds);
dc=uint8(n_bit_decoding(data,6,8,salt))';


mversion=sscanf(version('-release'),'%d%c');

if mversion(1)>=2009 && mversion(1)<2015,
   num_labs = matlabpool('size');
   if num_labs==0,
      matlabpool open
      num_labs = matlabpool('size');
      %num_labs=1;
   end;
elseif mversion(1)>=2015,
    poolobj = gcp('nocreate'); % If no pool, do not create new one.
    if isempty(poolobj)
        num_labs = 0;
        delete(poolobj);
    else
        num_labs = poolobj.NumWorkers;
    end;
    if num_labs==0,
        parpool('local');
        poolobj = gcp('nocreate'); % If no pool, do not create new one.
        num_labs = poolobj.NumWorkers;
    end;
else
   num_labs=0;
end;


if num_labs==0,
   figure;
   fignr=gcf;
   set(gcf,'Tag',['FIG',int2str(gcf)]);
   clf;
   set(gcf,'Position',[491 361 206 35]);
   set(gcf,'MenuBar','none');
   set(gcf,'NumberTitle','off');
   set(gcf,'Name','Progress:');
   c_text=uicontrol;
   set(c_text,'Tag',['C_TEXT',int2str(gcf)]);
   set(c_text,'Units','centimeters');
   set(c_text,'style','text');
   set(c_text,'string','0');
   set(c_text,'Position',[0.1 0.1 4.1 0.4]);
   set(c_text,'BackgroundColor',[1 1 1]);
   set(c_text,'Visible','on');
   pause(0.1);
end;

%** do rsa decoding:
c_package_byte_length=round(key.bit_length/8);
Nmessages=round(length(dc)/c_package_byte_length);
data=uint8(zeros(key.m_package_byte_length,Nmessages));
dc=reshape(dc,c_package_byte_length,Nmessages);
exponent1=key.exponent1;
prime1=key.prime1;
exponent2=key.exponent2;
prime2=key.prime2;
coefficient=key.coefficient;
modulus=key.modulus;
publicExponent=key.publicExponent;
if modus==0 && isempty(exponent1),
   error('public key cannot be used for decoding!');
end;


if mversion(1)>=2009,                %****  matlab with parallel toolbox
   parfor i=1:Nmessages,

      if num_labs==0 && mod(floor(i/Nmessages*1000),5)==0,
         c_text=findobj('Tag',['C_TEXT',int2str(gcf)]);
         set(c_text,'string',sprintf('%d/%d=%5.2f%%\n',i,Nmessages,floor(i/Nmessages*100+0.1)));
         pause(0.1);
      end;

      CODE=dc(:,i)';
      if CODE(1)>127,
         CODE=[uint8(0),CODE];
      end;
      if modus==0,
         MESSAGE=chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
      else
         MESSAGE=XXXInt_pow_mod(CODE,publicExponent,modulus);
      end;
      MESSAGE=MESSAGE(length(MESSAGE)-key.m_package_byte_length+(1:key.m_package_byte_length));
      data(:,i)=MESSAGE;
   end;
   %matlabpool close



else                           %****  matlab without parallel toolbox
   for i=1:Nmessages,

      if num_labs==0 && mod(floor(i/Nmessages*1000),5)==0,
         c_text=findobj('Tag',['C_TEXT',int2str(gcf)]);
         set(c_text,'string',sprintf('%d/%d=%5.2f%%\n',i,Nmessages,floor(i/Nmessages*100+0.1)));
         pause(0.1);
      end;

      CODE=dc(:,i)';
      if CODE(1)>127,
         CODE=[uint8(0),CODE];
      end;
      if modus==0,
         MESSAGE=chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
      else
         MESSAGE=XXXInt_pow_mod(CODE,publicExponent,modulus);
      end;
      MESSAGE=MESSAGE(length(MESSAGE)-key.m_package_byte_length+(1:key.m_package_byte_length));
      data(:,i)=MESSAGE;
   end;
end;
data=reshape(data,1,key.m_package_byte_length*Nmessages);
if num_labs==0,
   delete(fignr);
end;

% cut of leading zeros and the leading 1 
i=find(data>0,1,'first')+1;
data=double(data(i:end));


fid=fopen(outname,'wb');
fwrite(fid,data,'uint8');
fclose(fid);

fid=fopen(outname,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid)/8;
fseek(fid,0,'bof');
data=fread(fid,cnt,'double');
fclose(fid);

data=filter_decoding(data,key.modulus,salt);
data=round(data);

if write_to_file,
   fid=fopen(outname,'wb');
   fwrite(fid,data,'uint8');
   fclose(fid);
else
   delete(outname);
end;
res=real(data)';

end



function res=encode_file(filename,outname,key,start_ptr,salt,modus)

write_to_file=~strcmp('return',strtrim(lower(outname)));
if ~write_to_file,
   dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
   if exist(dirn,'dir')~=7,
      mkdir(dirn);
   end;
   outname=[dirn,'\tmptmp.code'];
end;

fid=fopen(filename,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid);
fseek(fid,start_ptr,'bof');
data=fread(fid);
fclose(fid);

y=filter_coding(data,key.modulus,salt);


fid=fopen(outname,'wb');
fwrite(fid,y,'double');
fclose(fid);

fid=fopen(outname,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid);
fseek(fid,0,'bof');
data=uint8(fread(fid,cnt,'uint8'));
fclose(fid);

%write the leading 1:
data=[uint8(1),data'];


% increase the length of the data to a multiple of key.m_package_byte_length
L=length(data);
Nmessages=ceil(L/key.m_package_byte_length);
incb=Nmessages*key.m_package_byte_length-L;
if incb>0,
   data=[uint8(zeros(1,incb)),data];
end;


mversion=sscanf(version('-release'),'%d%c');

if mversion(1)>=2009 && mversion(1)<2015,
   num_labs = matlabpool('size');
   if num_labs==0,
      matlabpool open
      num_labs = matlabpool('size');
      %num_labs=1;
   end;
elseif mversion(1)>=2015,
    poolobj = gcp('nocreate'); % If no pool, do not create new one.
    if isempty(poolobj)
        num_labs = 0;
        delete(poolobj);
    else
        num_labs = poolobj.NumWorkers;
    end;
    if num_labs==0,
        parpool('local');
        poolobj = gcp('nocreate'); % If no pool, do not create new one.
        num_labs = poolobj.NumWorkers;
    end;
else
   num_labs=0;
end;


if num_labs==0,
   figure;
   fignr=gcf;
   set(gcf,'Tag',['FIG',int2str(gcf)]);
   clf;
   set(gcf,'Position',[491 361 206 35]);
   set(gcf,'MenuBar','none');
   set(gcf,'NumberTitle','off');
   set(gcf,'Name','Progress:');
   c_text=uicontrol;
   set(c_text,'Tag',['C_TEXT',int2str(gcf)]);
   set(c_text,'Units','centimeters');
   set(c_text,'style','text');
   set(c_text,'string','0');
   set(c_text,'Position',[0.1 0.1 4.1 0.4]);
   set(c_text,'BackgroundColor',[1 1 1]);
   set(c_text,'Visible','on');
   pause(0.1);
end;

%** do rsa coding:
c_package_byte_length=round(key.bit_length/8);
dc=uint8(zeros(c_package_byte_length,Nmessages));
data=reshape(data,key.m_package_byte_length,Nmessages);
publicExponent=key.publicExponent;
modulus=key.modulus;
exponent1=key.exponent1;
prime1=key.prime1;
exponent2=key.exponent2;
prime2=key.prime2;
coefficient=key.coefficient;
if modus==1 && isempty(exponent1),
   error('public key cannot be used for encoding!');
end;


if mversion(1)>=2009,           %****  matlab with parallel toolbox
   parfor i=1:Nmessages,

      if num_labs==0 && mod(floor(i/Nmessages*1000),5)==0,
         c_text=findobj('Tag',['C_TEXT',int2str(gcf)]);
         set(c_text,'string',sprintf('%d/%d=%5.2f%%\n',i,Nmessages,floor(i/Nmessages*100+0.1)));
         pause(0.1);
      end;

      MESSAGE=data(:,i)';
      if MESSAGE(1)>127,
         MESSAGE=[uint8(0),MESSAGE];
      end;
      if modus==0,
         CODE=XXXInt_pow_mod(MESSAGE,publicExponent,modulus);
      else
         CODE=chr_decode(MESSAGE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
      end;
      CODE=CODE(length(CODE)-c_package_byte_length+(1:c_package_byte_length));
      dc(:,i)=CODE;
   end;
   %matlabpool close



else   %****  matlab without parallel toolbox
   for i=1:Nmessages,

      if num_labs==0 && mod(floor(i/Nmessages*1000),5)==0,
         c_text=findobj('Tag',['C_TEXT',int2str(gcf)]);
         set(c_text,'string',sprintf('%d/%d=%5.2f%%\n',i,Nmessages,floor(i/Nmessages*100+0.1)));
         pause(0.1);
      end;

      MESSAGE=data(:,i)';
      if MESSAGE(1)>127,
         MESSAGE=[uint8(0),MESSAGE];
      end;
      if modus==0,
         CODE=XXXInt_pow_mod(MESSAGE,publicExponent,modulus);
      else
         CODE=chr_decode(MESSAGE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
      end;
      CODE=CODE(length(CODE)-c_package_byte_length+(1:c_package_byte_length));
      dc(:,i)=CODE;
   end;
end;


dc=reshape(dc,1,c_package_byte_length*Nmessages);
if num_labs==0,
   delete(fignr);
end;

dd=n_bit_coding(dc,8,6,salt);
ds=convert_double_to_char_vector(dd,20);

if write_to_file,
   ds=[ds,char(repmat(10,size(ds,1),1))];
   ds=double(ds);
   fid=fopen(outname,'wb');
   fwrite(fid,ds','char');
   fclose(fid);
else
   delete(outname);
end;
res=ds;
end

function s=openssl_dirlist()
s={'c:\Program Files (x86)\Apache Software Foundation\Apache2.4\bin'};
end

function key_txt=generate_key(bit_length)

if nargin<1 || isempty(bit_length),
   bit_length=384;  % smallest possible bitlength of rsa key in openssl 
end;

progdir=openssl_dirlist();
progdir=get_first_existent_directory(progdir);
if exist(progdir,'dir')~=7,
   error('%s does not exist!',prodir);
end;
dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;
dirn_uinx_filesep=rep_sstr(dirn,'\','/');


dosbatch_fname=[dirn,'\doscmdfile.bat'];

%*** create the openssl keyfile  *.pem ****
generate_certification_request=false;  

fid=fopen(dosbatch_fname,'wt');
fprintf(fid,'cd %s\n',dirn);
fprintf(fid,'%s\n',getenv('HOMEDRIVE'));
fprintf(fid,'set PATH=%%PATH%%;"%s";\n',progdir);

fprintf(fid,'set RANDFILE=.rnd\n');
if generate_certification_request,
   fprintf(fid,'openssl req -newkey rsa:%d -out "%s/test.csr" \n',bit_length,dirn_uinx_filesep);
   waitfile='test.csr';
else
   fprintf(fid,'openssl genrsa -des3 -out "%s/privkey.pem"  %d \n',dirn_uinx_filesep,bit_length);
   waitfile='privkey.pem';
end;
fclose(fid);
if exist([dirn,'\',waitfile],'file')==2,
   delete([dirn,'\',waitfile]);
end;
dos(sprintf('cmd /C %s &',dosbatch_fname),'-echo');

while exist([dirn,'\',waitfile],'file')~=2,
   %fprintf('******\n');
   pause(0.2);
end;
while true,
   di=dir([dirn,'\privkey.pem']);
   if di.bytes>1,
      break;
   end;
   %fprintf('-------\n');
   pause(0.2);
end;
pause(1);
delete(dosbatch_fname);
delete([dirn,'\.rnd']);
[tmp1,tmp2]=dos('@Taskkill /IM cmd.exe /F >nul','-echo');


%*** create the openssl keyfile  *.txt for the private key ****
fid=fopen(dosbatch_fname,'wt');
fprintf(fid,'cd %s\n',dirn);
fprintf(fid,'%s\n',getenv('HOMEDRIVE'));
fprintf(fid,'set PATH=%%PATH%%;"%s";\n',progdir);

fprintf(fid,'openssl rsa -text -out "%s/privkey.txt" -in "%s/privkey.pem"  \n' ...
   ,dirn_uinx_filesep,dirn_uinx_filesep);
waitfile='privkey.txt';

fclose(fid);
if exist([dirn,'\',waitfile],'file')==2,
   delete([dirn,'\',waitfile]);
end;
dos(sprintf('cmd /C %s &',dosbatch_fname),'-echo');

while exist([dirn,'\',waitfile],'file')~=2,
   %fprintf('******\n');
   pause(0.2);
end;
while true,
   di=dir([dirn,'\privkey.txt']);
   if di.bytes>1,
      break;
   end;
   %fprintf('-------\n');
   pause(0.2);
end;
delete(dosbatch_fname);
[tmp1,tmp2]=dos('@Taskkill /IM cmd.exe /F >nul','-echo');



key_txt=t_read([dirn,'\privkey.txt'],10);
delete([dirn,'\privkey.txt']);
delete([dirn,'\privkey.pem']);


end


function write_txt_key(fid,priv_key_txt,pub_only)
if ~pub_only,
   for i=1:size(priv_key_txt,1),
      k = strfind(priv_key_txt(i,:), 'BEGIN RSA PRIVATE KEY');
      if ~isempty(k),
         break;
      end;
      fprintf(fid,'%s%c',priv_key_txt(i,:),10);
   end;
else
   privkey=read_txt_keyfile(priv_key_txt,false);
   fprintf(fid,'Public-Key: (%d bit) %c',privkey.bit_length,10);
   write_byte_sequence(fid,privkey.modulus,'modulus');
   hs=[];
   fact=uint32(1);
   decval=uint32(0);
   for k=length(privkey.publicExponent):-1:1,
      decval=decval+fact*uint32(privkey.publicExponent(k));
      fact=fact*uint32(255);
      bs=lower(dec2hex(privkey.publicExponent(k)));
      if length(bs)<2,
         bs=['0',bs];
      end;
      hs=[bs,hs];
   end;
   fprintf(fid,'publicExponent: %d (0x%s)%c',decval,hs,10);
end;
end


function generate_key_files(key_name,bit_length)
% generates a pair of public and private keys and stores them in two different file:
%  The public key in: 
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',key_name,'.pub.code']
%  The private and the public key in:
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\',key_name,'.priv.code']
%  The key_name and the corresponding filenames of these codes are also stored in 
%             [getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory\key_identifiers.mat']
%  DO NOT ALLOW ANYBODY EXCEPT YOURSELF ACCESS TO THIS DIRECTORY FOR SECURITY REASONS !!!!!!!
%     bit_length: bit length of the generated key (default: 384)
if nargin<1 || isempty(key_name),
   key_name=' ';
end;
key_name=strtrim(lower(key_name));
if isempty(key_name),
   error('my_email_adress is empty!!!');
end;
if nargin<2,
   bit_length=[];
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
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i>0,
      resp=questdlg(sprintf('%s found in key_identifier file! Do you want to overwrite the content?',key_name),' ','Yes','No','No');
      if isempty(resp) || strcmp(resp,'No');
         return;
      end;
   end;
   if  ~strcmp(key_name,default_privID) && ~isempty(default_privID),
      resp=questdlg(sprintf('Your present default private key is %s. Do you want to change it to %s ?',default_privID,key_name),' ','Yes','No','No');
      replace_default_privID=(~isempty(resp) && ~strcmp(resp,'No'));
   end;
   if strcmp(key_name,default_privID),
      replace_default_privID=false;
   end;
end;


key_txt=generate_key(bit_length);


outfile=[dirn,'\',key_name,'.pub'];
fid=fopen(outfile,'wt');
fprintf(fid,'%s%c',key_name,10);
write_txt_key(fid,key_txt,true);
fclose(fid);

outfile_pub_code=RsaCoder(outfile,1,'encode',1);
delete(outfile);
%RsaCoder(outfile_pub_code,-1,'decode',1,'return')

outfile=[dirn,'\',key_name,'.priv'];
fid=fopen(outfile,'wt');
fprintf(fid,'%s%c',key_name,10);
write_txt_key(fid,key_txt,false);
fclose(fid);

outfile_priv_code=RsaCoder(outfile,1,'encode',1);
delete(outfile);
%RsaCoder(outfile_priv_code,-1,'decode',1,'return')


[fp,fn,fe]=fileparts(outfile_priv_code);
outfile_priv_code=[fn,fe];
[fp,fn,fe]=fileparts(outfile_pub_code);
outfile_pub_code=[fn,fe];

if exist(matfile,'file')~=2,
   keyID={key_name,outfile_pub_code,outfile_priv_code};
else
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i<0,
      i=size(keyID,1)+1;
   end;
   keyID{i,1}=key_name;
   keyID{i,2}=outfile_pub_code;
   keyID{i,3}=outfile_priv_code;
end;
if replace_default_privID,
   if isempty(default_privID),
      warndlg(sprintf('Default privat key has been set to %s',key_name),'!! Info !!')
   else
      warndlg(sprintf('Old default privat key %s has been modified to %s',default_privID,key_name),'!! Info !!')
   end;
   default_privID=key_name;
end;
if warn_for_PrivatKeyUpdate,
   warndlg(sprintf('Privat key has been modified. Remember to send %s to all who want to send mails to %s!',outfile_pub_code,key_name),'!! Info !!')
end;
save(matfile,'keyID','default_privID');
end




function res=encode_data(filename,key_name)
%             If exist(key_name,'file')==2, the public key is retrieved from that file
%             key_name='select' allows to interactively select the key.priv.code file.

if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(key_name),
   key_name=' ';
end;


key_name=strtrim(lower(key_name));
if isempty(key_name),
   error('key_name is empty!!!');
end;

if strcmp(strtrim(lower(key_name)),'select'),
   mask='*.code';
   title_str='Load Key-File:';
   eval(['[key_name, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(key_name,0)|| isequal(key_name,0),
      return;
   end;
   key_name=[pathname,key_name];
   if isempty(key_name),
      res=[];
      return;
   end;
end;

filename=strtrim(filename);
if exist(filename,'file')~=2,
   error(sprintf('%s does not exist!',filename));
end;

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

if exist(key_name,'file')~=2,
   %** retrieve public key of recipient:
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run import_key(address.pub.code)!');
   end;
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i<0,
      error(sprintf('%s not found in key_identifier file. Check spelling or run import_key(address.pub.code)!',key_name));
   end;
   
   outfile_pub_code=[dirn,filesep,keyID{i,2}];
else
   outfile_pub_code=key_name;
end;

outf_decode=RsaCoder(outfile_pub_code,-1,'decode',1);
key=read_txt_keyfile(outf_decode,false);
delete(outf_decode);

res=RsaCoder(filename,key,'encode',0);
if nargout<1,
   warndlg(sprintf('Encoded file written to %s .',res),'!! Info !!')
end;

end

function res=decode_data(filename,outfile,key_name)
%res=decode_data(filename,outfile,key_name)
%  filename: name of coded file
%   outfile: where to place the output:  'return': output to command line  (default)
%                                          'auto': automatically generated filename
% key_name : private key identifier used for decoding.
%                     default: default public key as stored in the key_identifier file
%             If exist(key_name,'file')==2, the private key is retrieved from that file
%             key_name='select' allows to interactively select the key.priv.code file.
if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(outfile),
   outfile='return';
end;
if nargin<3 || isempty(key_name),
   key_name=' ';
end;

if strcmp(strtrim(lower(key_name)),'select'),
   mask='*.code';
   title_str='Load private Key-File:';
   eval(['[key_name, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(key_name,0)|| isequal(key_name,0),
      return;
   end;
   key_name=[pathname,key_name];
   if isempty(key_name),
      res=[];
      return;
   end;
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

if exist(key_name,'file')~=2,
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
   end;
   
   
   key_name=strtrim(lower(key_name));
   if isempty(key_name),
      default_privID=[];
      load(matfile,'default_privID');
      if isempty(default_privID),
         error('default_privID not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
      end;
      key_name=default_privID;
   end;
   
   
   %** retrieve my private key:
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i<0,
      error('%s not found in key_identifier file. Check spelling or run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!',key_name);
   end;
   
   if isempty(keyID{i,3}),
      error('The privat key %s is not known!',key_name);
   end;
   outfile_priv_code=[dirn,filesep,keyID{i,3}];
else
   outfile_priv_code=key_name;
end;

outf_decode=RsaCoder(outfile_priv_code,-1,'decode',1);
key=read_txt_keyfile(outf_decode,false);
delete(outf_decode);

res=RsaCoder(filename,key,'decode',0,outfile);
if nargout<1 && ~strcmp(outfile,'return'),
   warndlg(sprintf('Decoded file written to %s .',res),'!! Info !!')
end;

end


function manage_key()
%this deletes the entire line of key_name in the key_identifier file. It does not delete the coded key files itself!!!

key_name=' ';
key_name=strtrim(lower(key_name));


dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;


matfile=[dirn,'\key_identifiers.mat'];
if exist(matfile,'file')~=2,
   error('key_identifier file not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
end;

keyID=[];
default_privID=[];
load(matfile,'keyID','default_privID');



if nargin<1 || isempty(key_name),
   key_name=[];
   figure(1);
   set(gcf,'Position',[100,500,500,100],'name','delete key from database');
   h_popup=uicontrol(gcf,'style','popupmenu');
   set(h_popup,'Units','normalized');
   set(h_popup,'Position',[0.3 0.7 0.4 0.1]);
   set(h_popup,'CallBack',@cb_popup);
   ca=cell(1,size(keyID,1)+1);
   ca{1}='no file selected for delete';
   for i=2:size(keyID,1)+1,
      ca{i}=keyID{i-1,1};
      if strcmp(default_privID,keyID{i-1,1}),
         ca{i}=['default: ',ca{i}];
      elseif isempty(keyID{i-1,3}),
         ca{i}=['public: ',ca{i}];
      else
         ca{i}=['private: ',ca{i}];
      end;
   end;
   set(h_popup,'String',ca);
   set(h_popup,'Value',1);
   
   
   
   exit_button=uicontrol;
   set(exit_button,'Units','normalized' ...
   ,'string','Exit' ...
   ,'Position',[0.8 0.6 0.1 0.3] ...
   ,'CallBack',@cb_exit);

   
   pubConvert_button=uicontrol;
   set(pubConvert_button,'Units','normalized' ...
   ,'string','-> public' ...
   ,'Position',[0.8 0.1 0.1 0.3] ...
   ,'CallBack',@cb_pubConvert ...
   ,'Enable','off');
   
   gui_wait_exit_value=[];
   
   while isempty(gui_wait_exit_value),
      pause(0.2);
   end;
end;


if isempty(key_name),
   return;
end;

key_name=strtrim(lower(key_name));

i=-1;
for k=1:size(keyID,1),
   if strcmp(keyID{k,1},key_name),
      i=k;
      break;
   end;
end;
if i<0,
   error('%s not found in key_identifier file',key_name);
end;

switch gui_wait_exit_value,
   case 'delete',
      if strcmp(default_privID,key_name),
         default_privID=[];
         warndlg(sprintf('The default privat key %s has been deleted in the key_identifier file. To reestablish the default privat key run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!',key_name),'!! Info !!');
      end;
      
      if size(keyID,1)<2,
         delete(matfile);
         return;
      end;
      keyID=keyID(setdiff(1:size(keyID,1),i),:);
   case 'convert_to_public',
      if strcmp(default_privID,key_name),
         warndlg(sprintf('The default privat key %s has been converted in a public key. To reestablish the default privat key run rsa_generate_key_files(my_email_address) or rsa_import_key(address.priv.code)!',key_name),'!! Info !!');
         %return;
         default_privID=[];
      end;
      keyID{i,3}='';
   otherwise
      error('invalid gui_wait_exit_value: %s',gui_wait_exit_value);
end;
save(matfile,'keyID','default_privID');


   function cb_pubConvert(hObject, eventdata, handles)
      gui_wait_exit_value='convert_to_public';
      delete(1);
   end


   function cb_exit(hObject, eventdata, handles)
      gui_wait_exit_value='delete';
      delete(1);
   end

   function cb_popup(hObject, eventdata, handles)
      actual_key_name_index = get(hObject,'Value')-1;
      if actual_key_name_index==0,
         actual_key_name_index=NaN;
         key_name=[];
         set(exit_button,'string','Exit');
         set(pubConvert_button,'Enable','off');
      else
         key_name=keyID{actual_key_name_index,1};
         set(exit_button,'string','Delete');
         if ~isempty(keyID{actual_key_name_index,3}),
            set(pubConvert_button,'Enable','on');
         else
            set(pubConvert_button,'Enable','off');
         end;
      end;
   end

end

function import_key(filename_code)
if nargin<1,
   filename_code=[];
end;


dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

ini_file=[dirn,'\rsa_inifile.mat'];


workdir=pwd;
ini_rsa_import_key_FileDLGDir=workdir;  %<= default setting
if exist(ini_file,'file')~=2,
   save(ini_file,'ini_rsa_import_key_FileDLGDir');
else
   tmp=load(ini_file);
   if isfield(tmp,'ini_rsa_import_key_FileDLGDir'),
      ini_rsa_import_key_FileDLGDir=tmp.ini_rsa_import_key_FileDLGDir;
   end;
   clear tmp
end;
cd(ini_rsa_import_key_FileDLGDir);

if isempty(filename_code),
   mask='*.code';
   title_str='Load Key-File:';
   eval(['[filename_code, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(filename_code,0)| isequal(filename_code,0),
      return;
   end;
   filename_code=[pathname,filename_code];
end;
if isempty(filename_code),
   return;
end;



cd(workdir);
ini_rsa_import_key_FileDLGDir=pathname;
if strcmp(ini_rsa_import_key_FileDLGDir(end),filesep),
   ini_rsa_import_key_FileDLGDir=ini_rsa_import_key_FileDLGDir(1:end-1);
end;
save(ini_file,'ini_rsa_import_key_FileDLGDir','-append');




if exist(filename_code,'file')~=2,
   error('File %s does not exist!',filename_code);
end;

matfile=[dirn,'\key_identifiers.mat'];

%** retrieve the data from the key file

outfile_code=filename_code;

outf_decode=RsaCoder(outfile_code,-1,'decode',1);
fid=fopen(outf_decode,'rt');
adr=fscanf(fid,'%s\n',1);
fclose(fid);
key_txt=t_read(outf_decode,10);
key=read_txt_keyfile(key_txt,false);

delete(outf_decode);

if isempty(adr) || isempty(key.publicExponent),
   error('%s is not a valid key file!');
end;

if isempty(key.prime1),  %<= this is a public key
   is_priv_code=false;
   outfile_pub_code=[dirn,'\',adr,'.pub.code'];
else
   outfile_priv_code=[dirn,'\',adr,'.priv.code'];
   is_priv_code=true;
end;

%** check how to insert filenames in the key_identifier file: 
default_privID=[];
replace_default_privID=is_priv_code;
warn_for_PrivatKeyUpdate=is_priv_code;
if exist(matfile,'file')==2,
   keyID=[];
   default_privID=[];
   load(matfile,'keyID','default_privID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},adr),
         i=k;
         break;
      end;
   end;
   if i>0,
      if ~isempty(keyID{i,3}) && ~is_priv_code,
         warning('import_key:PubOnPrivError','Can''t import public key on existent private key!');
         return;
      end;
      resp=questdlg(sprintf('%s found in key_identifier file! Do you want to overwrite the content?',adr),' ','Yes','No','No');
      if isempty(resp) || strcmp(resp,'No');
         return;
      end;
      if is_priv_code && ~strcmp(adr,default_privID) && ~isempty(default_privID),
         resp=questdlg(sprintf('Your present default private key is %s. Do you want to change it to %s ?',default_privID,adr),' ','Yes','No','No');
         replace_default_privID=(~isempty(resp) && ~strcmp(resp,'No'));
      end;
      if is_priv_code && strcmp(adr,default_privID),
         replace_default_privID=false;
      end;
      
      
      if ~isempty(keyID{i,3}) && is_priv_code,
         outfile_code=[dirn,filesep,keyID{i,3}];
         outf_decode=RsaCoder(outfile_code,-1,'decode',1);
         fid=fopen(outf_decode,'rt');
         adr1=fscanf(fid,'%s\n',1);
         fclose(fid);
         key_old=read_txt_keyfile(outf_decode,false);
         delete(outf_decode);
         warn_for_PrivatKeyUpdate=(any(key.modulus~=key_old.modulus) || any(key.publicExponent~=key_old.publicExponent));
      end;
            
      
      
   end;
end;

if is_priv_code,
   %** create the public key file: ***
   outfile=[dirn,'\',adr,'.pub'];
   fid=fopen(outfile,'wt');
   fprintf(fid,'%s%c',adr,10);
   write_txt_key(fid,key_txt,true);
   fclose(fid);
      
   outfile_pub_code=RsaCoder(outfile,1,'encode',1);
   delete(outfile);
else
   outfile_priv_code=[];
end;

if is_priv_code,
   copied_filename=outfile_priv_code;
else
   copied_filename=outfile_pub_code;
end;
if ~strcmp(filename_code,copied_filename)
   copyfile(filename_code,copied_filename);
   [fp,fn,fe]=fileparts(filename_code);
   filename_code_no_path=[fn,fe];
   [fp,fn,fe]=fileparts(copied_filename);
   copied_filename=[fn,fe];
   
   resp=questdlg(sprintf('original %s is copied to %s in your the private database. Do you want to delete the original? (recommended)',filename_code_no_path,copied_filename),' ','Yes','No','Yes');
   if isempty(resp) || strcmp(resp,'Yes');
      delete(filename_code);
   end;
end;

if ~isempty(outfile_priv_code),
   [fp,fn,fe]=fileparts(outfile_priv_code);
   outfile_priv_code=[fn,fe];
end;
[fp,fn,fe]=fileparts(outfile_pub_code);
outfile_pub_code=[fn,fe];



%*** update the key_identifier file: ***
if exist(matfile,'file')~=2,
   keyID={adr,outfile_pub_code,outfile_priv_code};
else
   keyID=[];
   default_privID=[];
   load(matfile,'keyID','default_privID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},adr),
         i=k;
         break;
      end;
   end;
   if i<0,
      i=size(keyID,1)+1;
   end;
   keyID{i,1}=adr;
   keyID{i,2}=outfile_pub_code;
   keyID{i,3}=outfile_priv_code;
end;
if replace_default_privID,
   if isempty(default_privID),
      warndlg(sprintf('Default privat key has been set to %s',adr),'!! Info !!')
   else
      warndlg(sprintf('Old default privat key %s has been modified to %s',default_privID,adr),'!! Info !!')
   end;
   default_privID=adr;
end;
if warn_for_PrivatKeyUpdate,
   warndlg(sprintf('Privat key has been modified. Consider sending %s to all who want to send mails to %s!',outfile_pub_code,adr),'!! Info !!')
end;
save(matfile,'keyID','default_privID');

end


function res=sign_data(filename,outfile,key_name)
%res=sign_data(filename,outfile,key_name)
%  filename: name of coded file
%   outfile: where to place the output:  'return': output to command line  
%                                          'auto': automatically generated filename  (default)
% key_name : private key identifier used for signature.
%                     default: default private key as stored in the key_identifier file
%            If exist(key_name,'file')==2, the private key is retrieved from that file
%            key_name='select' allows to interactively select the key.priv.code file.
if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(outfile),
   outfile='auto';
end;
if nargin<3 || isempty(key_name),
   key_name=' ';
end;

if strcmp(strtrim(lower(key_name)),'select'),
   mask='*.code';
   title_str='Load private Key-File:';
   eval(['[key_name, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(key_name,0)|| isequal(key_name,0),
      return;
   end;
   key_name=[pathname,key_name];
   if isempty(key_name),
      res=[];
      return;
   end;
end;

filename=strtrim(filename);
if exist(filename,'file')~=2,
   error(sprintf('%s does not exist!',filename));
end;


[fp,fn,fe]=fileparts(filename);
if isempty(fp),
    fp=pwd;
    filename=[fp,filesep,fn,fe];
end;

if strcmp(strtrim(lower(outfile)),'auto'),
   outfile=[fp,filesep,fn,fe,'.signed'];
end;
outfile=strtrim(lower(outfile));

dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

if exist(key_name,'file')~=2,
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
   end;
   
   
   key_name=strtrim(lower(key_name));
   if isempty(key_name),
      default_privID=[];
      load(matfile,'default_privID');
      if isempty(default_privID),
         error('default_privID not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
      end;
      key_name=default_privID;
   end;
   
   
   %** retrieve my private key:
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i<0,
      error('%s not found in key_identifier file. Check spelling or run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!',key_name);
   end;
   
   if isempty(keyID{i,3}),
      error('The privat key %s is not known!',key_name);
   end;
   outfile_priv_code=[dirn,filesep,keyID{i,3}];
else
   outfile_priv_code=key_name;
end;
outf_decode=RsaCoder(outfile_priv_code,-1,'decode',1);
fid=fopen(outf_decode,'rt');
key_name=fscanf(fid,'%s\n',1);
fclose(fid);
key=read_txt_keyfile(outf_decode,false);
key_txt=t_read(outf_decode,10);
delete(outf_decode);

progdir=openssl_dirlist();
progdir=get_first_existent_directory(progdir);
if exist(progdir,'dir')~=7,
   error('%s does not exist!',prodir);
end;


outfile_hash=[dirn,'\tmp_hash.txt'];
%** create the hash of the public key ***
outfile_pub_key=[dirn,'\tmp_key.pub'];
fid=fopen(outfile_pub_key,'wt');
fprintf(fid,'%s%c',key_name,10);
write_txt_key(fid,key_txt,true);
fclose(fid);
cmdstr=['"',progdir,'\openssl.exe" dgst -sha512 -hex -out ',outfile_hash,' ',outfile_pub_key];
dos(cmdstr);  
delete(outfile_pub_key);
hashstr_pub=t_read(outfile_hash);
hashstr_pub=hashstr_pub(1,:);
i=strfind(hashstr_pub,'=');
if isempty(i),
   error('hash pub string not found!');
end;
hashstr_pub=strtrim(hashstr_pub(i+1:end));
%*** create the hash of the file
cmdstr=['"',progdir,'\openssl.exe" dgst -sha512 -hex -out ',outfile_hash,' ',filename];
dos(cmdstr);  
hashstr=t_read(outfile_hash);
hashstr=hashstr(1,:);
i=strfind(hashstr,'=');
if isempty(i),
   error('hash string not found!');
end;
hashstr=strtrim(hashstr(i+1:end));
fid=fopen(outfile_hash,'wt');
fprintf(fid,'%s\n',hashstr);
fprintf(fid,'%s\n',hashstr_pub);
fclose(fid);



res=RsaCoder(outfile_hash,key,'encode',1,outfile);
if ~strcmp(strtrim(lower(res)),strtrim(lower(outfile))),
   copyfile(res,outfile);
   delete(res);
end;
delete(outfile_hash);
if nargout<1 && ~strcmp(outfile,'return'),
   warndlg(sprintf('Signed hash written to %s .',res),'!! Info !!')
end;

end

function [isvalid,check]=check_signed_data(filename,signature_file,key_name)
%check_signed_data=sign_data(filename,signature_file,key_name)
%        filename: name of file
%  signature_file: name of the signature file
% key_name : public key identifier. If exist(key_name,'file')==2, the public key is
%            retrieved from that file
%            key_name='select' allows to interactively select the key.priv.code file.

if nargin<1 || isempty(filename),
   filename=' ';
end;
if nargin<2 || isempty(signature_file),
   signature_file=' ';
end;
if nargin<3 || isempty(key_name),
   key_name=' ';
end;

if strcmp(strtrim(lower(key_name)),'select'),
   mask='*.code';
   title_str='Load Key-File:';
   eval(['[key_name, pathname]=uigetfile(''',mask,''', ''',title_str,''');']);
   if isequal(key_name,0)|| isequal(key_name,0),
      return;
   end;
   key_name=[pathname,key_name];
   if isempty(key_name),
      isvalid=[];
      check=[];
      return;
   end;
end;


filename=strtrim(filename);
if exist(filename,'file')~=2,
   error(sprintf('%s does not exist!',filename));
end;

signature_file=strtrim(signature_file);
if exist(signature_file,'file')~=2,
   error(sprintf('%s does not exist!',signature_file));
end;

[fp,fn,fe]=fileparts(filename);
if isempty(fp),
    fp=pwd;
    filename=[fp,filesep,fn,fe];
end;


dirn=[getenv('HOMEDRIVE'),getenv('HOMEPATH'),'\rsa_directory'];
if exist(dirn,'dir')~=7,
   mkdir(dirn);
end;

if exist(key_name,'file')~=2,
   matfile=[dirn,'\key_identifiers.mat'];
   if exist(matfile,'file')~=2,
      error('key_identifier file not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
   end;
   
   
   key_name=strtrim(lower(key_name));
   if isempty(key_name),
      default_privID=[];
      load(matfile,'default_privID');
      if isempty(default_privID),
         error('default_privID not found. For creating a new one, run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!');
      end;
      key_name=default_privID;
   end;
   
   
   %** retrieve public key:
   keyID=[];
   load(matfile,'keyID');
   i=-1;
   for k=1:size(keyID,1),
      if strcmp(keyID{k,1},key_name),
         i=k;
         break;
      end;
   end;
   if i<0,
      error('%s not found in key_identifier file. Check spelling or run generate_key_files(key_name[,bit_length]) or import_key(key_name.priv.code)!',key_name);
   end;
   
   if isempty(keyID{i,2}),
      error('The public key %s is not known!',key_name);
   end;
   file_pub_code=[dirn,filesep,keyID{i,2}];
else
   file_pub_code=key_name;
end;
outf_decode=RsaCoder(file_pub_code,-1,'decode',1);
fid=fopen(outf_decode,'rt');
key_name=fscanf(fid,'%s\n',1);
fclose(fid);
key=read_txt_keyfile(outf_decode,false);
key_txt=t_read(outf_decode,10);
delete(outf_decode);

progdir=openssl_dirlist();
progdir=get_first_existent_directory(progdir);
if exist(progdir,'dir')~=7,
   error('%s does not exist!',prodir);
end;

outfile_hash=[dirn,'\tmp_hash.txt'];
%** create the hash of the public key ***
outfile_pub_key=[dirn,'\tmp_key.pub'];
fid=fopen(outfile_pub_key,'wt');
fprintf(fid,'%s%c',key_name,10);
write_txt_key(fid,key_txt,true);
fclose(fid);
cmdstr=['"',progdir,'\openssl.exe" dgst -sha512 -hex -out ',outfile_hash,' ',outfile_pub_key];
dos(cmdstr);  
delete(outfile_pub_key);
hashstr_pub=t_read(outfile_hash);
hashstr_pub=hashstr_pub(1,:);
i=strfind(hashstr_pub,'=');
if isempty(i),
   error('hash pub string not found!');
end;
hashstr_pub=strtrim(hashstr_pub(i+1:end));

%*** create the hash of the file
cmdstr=['"',progdir,'\openssl.exe" dgst -sha512 -hex -out ',outfile_hash,' ',filename];
dos(cmdstr);  
hashstr=t_read(outfile_hash);
hashstr=hashstr(1,:);
i=strfind(hashstr,'=');
if isempty(i),
   error('hash string not found!');
end;
hashstr=strtrim(hashstr(i+1:end));
delete(outfile_hash);


hash_sign=RsaCoder(signature_file,key,'decode',1,'return');
i=find(double(hash_sign)==10);
res_all=[strcmp(hash_sign(1,1:i(1)-1),hashstr),strcmp(hash_sign(1,i(1)+1:i(2)-1),hashstr_pub)];
isvalid=all(res_all);
check.isvalid_pubkey_hash=res_all(2);
check.isvalid_file_hash=res_all(1);
end


function export_pub_from_priv_code(priv_code_filename)

if exist(priv_code_filename,'file')~=2,
   error('%s does not exist!');
end;

[fp,fn,fe]=fileparts(priv_code_filename);
if isempty(fp),
   fp=pwd;
end;
if ~strcmp(lower(fe),'.code'),
   error('extension of input filename unequals ''.code''');
end;
outfile_pub_key=[fp,filesep,fn];
[fp,fn,fe]=fileparts(outfile_pub_key);
if ~strcmp(lower(fe),'.priv'),
   error('extension of input filename unequals ''.priv.code''');
end;
outfile_pub_key=[fp,filesep,fn,'.pub'];

outf_decode=RsaCoder(priv_code_filename,-1,'decode',1);
fid=fopen(outf_decode,'rt');
key_name=fscanf(fid,'%s\n',1);
fclose(fid);
key=read_txt_keyfile(outf_decode,false);
key_txt=t_read(outf_decode,10);
delete(outf_decode);


fid=fopen(outfile_pub_key,'wt');
fprintf(fid,'%s%c',key_name,10);
write_txt_key(fid,key_txt,true);
fclose(fid);
outf_decode=RsaCoder(outfile_pub_key,1,'encode',1);
delete(outfile_pub_key);

end

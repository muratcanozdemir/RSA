function rsa_develop_interpret_key(type)
if nargin<1 || isempty(type),
   type=0;     %   0: test reading private key and coding/decoding
   %   1: test XXXInt_add/ binary_add
   %   2: test XXXInt_prod/ byte sequence product
   %   3: test binary subtraction
   %   4: test XXXInt_subtract/ binary division
   %   5: test bit sequence to byte sequence
   %   6: test byte sequence division
   %   7: test binary_pow_mod
   %   8: test XXXInt_pow_mod/ byte_sequence_pow_mod
   %   9: test XXXInt_complement/ binary_complement
   %  10: test XXXInt_subtract/ binary_subtract
   
end;

use_XXXInt_operators=true;

switch type,
   case 0,    % test reading private key and coding/decoding
      %rsa_key_text is a public key generated with
      %cd c:\Program Files (x86)\Apache Software Foundation\Apache2.4\bin
      %set RANDFILE=.rnd
      %openssl req -newkey rsa:384 -out test.csr
      %openssl rsa -text -noout -in privkey.pem
      %%
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
      
      rsal=rsa_lib();
      privkey=rsal.read_private_key(rsa_key_text);
      
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
         error('%s not found!!',keyword);
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
      fprintf('%s:\n',keyword);
      printf_byte_sequence(modulus);
      if modulus(1)>127,
         modulus=[uint8(0),modulus];
      end;
      
      byte_length=round(bit_length/16);
      keyword='exponent1';
      exponent1=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(exponent1);
      if exponent1(1)>127,
         exponent1=[uint8(0),exponent1];
      end;
      
      byte_length=round(bit_length/16);
      keyword='exponent2';
      exponent2=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(exponent2);
      if exponent2(1)>127,
         exponent2=[uint8(0),exponent2];
      end;
      
      byte_length=round(bit_length/8);
      keyword='privateExponent';
      privateExponent=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(privateExponent);
      if privateExponent(1)>127,
         privateExponent=[uint8(0),privateExponent];
      end;
      
      
      byte_length=round(bit_length/16);
      keyword='coefficient';
      coefficient=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(coefficient);
      if coefficient(1)>127,
         coefficient=[uint8(0),coefficient];
      end;
      
      byte_length=round(bit_length/16);
      keyword='prime1';
      prime1=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(prime1);
      if prime1(1)>127,
         prime1=[uint8(0),prime1];
      end;
      
      byte_length=round(bit_length/16);
      keyword='prime2';
      prime2=read_byte_sequence(rsa_key_text,keyword,byte_length);
      fprintf('%s:\n',keyword);
      printf_byte_sequence(prime2);
      if prime2(1)>127,
         prime2=[uint8(0),prime2];
      end;
      
      prod=prod_byte_sequence(prime1,prime2);
      fprintf('%s:\n','prime1*prime2');
      printf_byte_sequence(prod);
      if isequal_byte_sequence(prod,modulus),
         fprintf('prime1*prime2 == modulus\n');
      end;
      
      
      X1=byte_sequence_sub(prime1,uint8(1));
      [Q,R]=divide_byte_sequence(privateExponent,X1);
      if isequal_byte_sequence(R,exponent1),
         fprintf('exponent1=privateExponent mod (prime1-1)\n');
      end;
      
      X1=byte_sequence_sub(prime2,uint8(1));
      [Q,R]=divide_byte_sequence(privateExponent,X1);
      if isequal_byte_sequence(R,exponent2),
         fprintf('exponent2=privateExponent mod (prime2-1)\n');
      end;
      
      
      prod=prod_byte_sequence(coefficient,prime2);
      [Q,I]=divide_byte_sequence(prod,prime1);
      
      if isequal_byte_sequence(I,uint8(1)),
         fprintf('coefficient*prime2 mod prime1 == 1\n');
      end;
      
      
      if true,  %** coding/decoding
         MESSAGE=uint8(floor(rand(1,47)*(2^8)));
         %MESSAGE=uint8(floor(rand(1,17)*(2^8)));
         if MESSAGE(1)>127,
            MESSAGE=[uint8(0),MESSAGE];
         end;
         %MESSAGE=uint8([0  208   62  237   89   50   64  157  121   90  212  149  140  234   73  193  192   97]);
         %MESSAGE=uint8([14, 111,54,254]);
         %MESSAGE
         if use_XXXInt_operators,
            CODE=XXXInt_pow_mod(MESSAGE,publicExponent,modulus);
         else
            CODE=byte_sequence_pow_mod(MESSAGE,publicExponent,modulus);
         end;
         %inversion using chinese remainder:
         tic
         if use_XXXInt_operators,
            DECODE1=rsal.chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
         else
            DECODE1=byte_sequence_rsa_chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus);
         end;
         toc
         %***************************************
         if ~rsal.isequal_byte_sequence(MESSAGE,DECODE1),
            warning('MESSAGE~=DECODE1');
         else
            fprintf('MESSAGE==DECODE1\n');
         end;
         
         
         %** direct inversion:
         tic
         if use_XXXInt_operators,
            DECODE=XXXInt_pow_mod(CODE,privateExponent,modulus);
         else
            DECODE=byte_sequence_pow_mod(CODE,privateExponent,modulus);
         end;
         toc
         %******************
         if ~rsal.isequal_byte_sequence(MESSAGE,DECODE),
            warning('MESSAGE~=DECODE');
         else
            fprintf('MESSAGE==DECODE\n');
         end;
      end;
      
      %  sq1=uint8(repmat(255,1,8));
      %  x=uint8_seq_2_uint64(sq1)   % this prints the maximum uint64  = 18446744073709551615
      %
      % sq1=uint8(repmat(255,1,7));
      % sq1(1)=uint8(15);
      % byte_sequence_to_bit_sequence(sq1)
      % x=uint8_seq_2_uint64(sq1)   % this prints the maximum uint52  = 4503599627370495
      
      
   case 1, %** check binary_add/ XXXInt_add
      N=10;
      X1=uint8(floor(rand(1,N)*2^8));
      X2=uint8(floor(rand(1,N)*2^8));
      %   X1(1)=bitor(128,X1(1)); % negative number
      X1(1)=bitand(127,X1(1)); % positive number
      X2(1)=bitand(127,X2(1)); % positive number
      x1=byte_sequence_to_bit_sequence(X1);
      x1=x1(2:end);  % do not convert to a positive number
      x2=byte_sequence_to_bit_sequence(X2);
      x2=x2(2:end);  % do not convert to a positive number
      
      x3=binary_add_mex(x1,x2);
      % convert result to byte sequence
      m8=mod(length(x3),8);
      if m8>0,
         x3=[repmat(x3(1),1,8-m8),x3];
      end;
      N1=floor(length(x3)/8);
      X3_=uint8(zeros(1,N1));
      for k=0:N1-1,
         X3_(k+1)=uint8(binary_to_uint64(x3(k*8+(1:8))));
      end;
      %******
      
      [X3,X3L]=XXXInt_add(X1,X2);
      
      if ~isequal_byte_sequence(X3,X3_),
         warning('X3_~=X3');
         %    else
         %       fprintf('X3_==X3\n');
      end;
      fprintf('X3L=%d\n',X3L);
      printf_byte_sequence(X3);
      printf_byte_sequence(X3_);
      
      
   case 2,   %** check byte sequence product
      tic
      for kj=1:30,
         ui1=uint64(floor(rand(1,1)*(2^40)));
         ui2=uint64(floor(rand(1,1)*(2^20)));
%          ui1=uint64(6474469412);
%          ui2=uint64(2799956020);
         seq1=uint64_2_uint8_seq(ui1);
         seq2=uint64_2_uint8_seq(ui2);
         %       ui2
         %       ui2-uint8_seq_2_double(seq2)
         if use_XXXInt_operators,
            prod=XXXInt_prod(seq1,seq2);
         else
            prod=prod_byte_sequence(seq1,seq2);
         end;
         x=ui1*ui2;
         x1=uint8_seq_2_uint64(prod);
         if x1~=x,
            error('x1=%d, x=%d\n',x1,x);
         end;
      end;
      toc
      
   case 3,  % test binary subtraction
      % b1=logical([0 0 0 1]);
      % bc1=binary_complement(b1)
      % b2=logical([0 0 1 0])
      % binary_add_mex(b2,bc1)
      tic
      for k=1:1,
         x1=uint64(floor(rand(1,1)*(2^32-1))+1);
         x2=uint64(floor(rand(1,1)*(2^32-1))+1);
         % if x2<x1,
         %    tmp=x1;
         %    x1=x2;
         %    x2=tmp;
         % end
         %      x1
         %      x2
         b1=uint_to_binary(x1,32);
         
         b2=uint_to_binary(x2,32);
         xi2=binary_to_uint64(b2)
         
         b3=binary_subtract(b2,b1);
         
         x3=binary_to_double(b3);
         
         if int64(x2)-int64(x1)~=x3,
            error('****');
         end;
      end;
      toc
      
      
   case 4,  % 4: test XXXInt_divide/binary division
      mq=-inf;
      NBits=63;
      tic
      for k=1:1,
         x1=uint64(floor(rand(1,1)*(2^NBits-1))+1);
         x2=uint64(floor(rand(1,1)*(2^NBits-1))+1);
%          x1=uint64(13820);
%          x2=uint64(30006);
%          x1=uint64(196);
%          x2=uint64(13946);
         
         if x2<x1,
            tmp=x1;
            x1=x2;
            x2=tmp;
         end;
         b1=uint_to_binary(x1,NBits);
         b2=uint_to_binary(x2,NBits);
         B1=bit_sequence_to_byte_sequence(b1);
         B2=bit_sequence_to_byte_sequence(b2);
         
         [Q,R]=binary_divide(b2,b1);
         [QXI,RXI]=XXXInt_divide(B2,B1);
         QXI_=bit_sequence_to_byte_sequence(Q);
         RXI_=bit_sequence_to_byte_sequence(R);
         if ~isequal_byte_sequence(RXI_,RXI),
            warning('RXI_~=RXI');
            fprintf('x1=%d, x2=%d\n',x1,x2);
         end;
         if ~isequal_byte_sequence(QXI_,QXI),
            warning('QXI_~=QXI');
         end;
         xQ=binary_to_double(Q);
         mq=max(mq,xQ);
         xQ1=floor(double(x2)/double(x1));
         xR=binary_to_uint64(R);
         
         xR1=mod(x2,x1);
         if xR~=xR1 || xQ~=xQ1,
            x1
            x2
            xQ1
            xR1
            error('*******');
         end;
      end;
      toc
      
      
   case 5, % test bit sequence to byte sequence
      NBits=17;
      x1=uint64(floor(rand(1,1)*(2^NBits-1))+1);
      D=uint64_2_uint8_seq(x1)
      Db=byte_sequence_to_bit_sequence(D);
      D1=bit_sequence_to_byte_sequence(Db)
      
   case 6,   % check byte sequence division
      NBits=8;
      NBytes=400;
      
      tic;
      for k=1:10,
         
         %       x1=uint64(floor(rand(1,1)*(2^NBits-1))+1);
         %       x2=uint64(floor(rand(1,1)*(2^NBits-1))+1);
         %
         %       X1=uint64_2_uint8_seq(x1);
         %       X2=uint64_2_uint8_seq(x2);
         
         X1=uint8(floor(rand(1,7)*(2^NBits)));
         X2=uint8(floor(rand(1,NBytes)*(2^NBits)));
         if X1(1)>127, X1=[uint8(0),X1]; end;
         if X2(1)>127, X2=[uint8(0),X2]; end;
         if use_XXXInt_operators,
            [Q,R]=XXXInt_divide(X2,X1);
         else
            [Q,R]=divide_byte_sequence(X2,X1);
         end;
         
         PR=prod_byte_sequence(X1,Q);
         if use_XXXInt_operators,
            X2T=XXXInt_add(PR,R);
         else
            X2T=add_byte_sequence(PR,R);
         end;
         
         if ~isequal_byte_sequence(X2T,X2),
            error('*******');
         end;
         
      end;
      time_elapsed=toc;
      
      fprintf('%s:\n','X2');
      printf_byte_sequence(X2);
      fprintf('%s:\n','X2T');
      printf_byte_sequence(X2T);
      length(X1)
      fprintf('Elapsed time is %.6f seconds.\n',time_elapsed);
   case 7, % test binary_pow_mod
      NBits=22;
      
      x1=uint64(floor(rand(1,1)*(2^NBits-1))+1);
      x2=uint64(floor(rand(1,1)*(2^NBits-1))+1);
      mui=uint64(floor(rand(1,1)*(2^6-1))+1);
      b1=uint_to_binary(x1,NBits);
      b2=uint_to_binary(x2,NBits);
      m=uint_to_binary(mui,6);
      tic
      x3=binary_pow_mod(b1,b2,m)
      toc
      tic
      x3ui=1;
      for k=1:x2,
         x3ui=uint64(mod(x3ui*x1,mui));
      end;
      toc
      if x3ui~=binary_to_uint64(x3),
         error('****');
      end;
      
   case 8, % test XXXInt_pow_mod/ byte_sequence_pow_mod
      NBits=17;
      for kj=1:100,
         x1=uint64(floor(rand(1,1)*(2^NBits-1))+1);
         x2=uint64(floor(rand(1,1)*(2^6-1))+1);
         mui=uint64(floor(rand(1,1)*(2^12-1))+1);
         
         %x1=uint64(126469); x2=uint64(20659);  mui=uint64(47);
         fprintf('x1=uint64(%d); x2=uint64(%d);  mui=uint64(%d);\n',x1,x2,mui);
         X1=uint64_2_uint8_seq(x1);
         X2=uint64_2_uint8_seq(x2);
         M=uint64_2_uint8_seq(mui);
         if use_XXXInt_operators,
            X3=XXXInt_pow_mod(X1,X2,M);
         else
            X3=byte_sequence_pow_mod(X1,X2,M);
         end;
         x3ui=1;
         for k=1:x2,
            x3ui=uint64(mod(x3ui*x1,mui));
         end;
         X3T=uint64_2_uint8_seq(x3ui);
         
         if ~isequal_byte_sequence(X3T,X3),
            error('*******');
         end;
      end;
      
      
   case 9,  % test XXInt_complement/ binary_complement
      N=5;
      X1=uint8(floor(rand(1,N)*2^8));
      X1(1)=bitor(128,X1(1)); % negative number
      %X1(1)=bitand(127,X1(1)); % positive number
      x1=byte_sequence_to_bit_sequence(X1);
      x1=x1(2:end);  % do not convert to a positive number
      
      
      x3_=binary_complement(x1);
      % convert result to byte sequence
      m8=mod(length(x3_),8);
      if m8>0,
         x3_=[repmat(x3_(1),1,8-m8),x3_];
      end;
      N1=floor(length(x3_)/8);
      X3_=uint8(zeros(1,N1));
      for k=0:N1-1,
         X3_(k+1)=uint8(binary_to_uint64(x3_(k*8+(1:8))));
      end;
      %******
      
      X3=XXXInt_complement(X1);
      x3=byte_sequence_to_bit_sequence(X3);
      x3=x3(2:end);  % do not convert to a positive number
      
      if ~isequal_byte_sequence(X3,X3_),
         warning('X3_~=X3');
         %    else
         %       fprintf('X3_==X3\n');
      end;
      printf_byte_sequence(X3);
      printf_byte_sequence(X3_);
      x1
      x3_
      
      
   case 10, %** test binary_subtract/ XXXInt_subtract
      N=3;
      X1=uint8(floor(rand(1,N)*2^8));
      X2=uint8(floor(rand(1,N)*2^8));
      X1(1)=bitor(128,X1(1)); % negative number
      %X1(1)=bitand(127,X1(1)); % positive number
      X2(1)=bitand(127,X2(1)); % positive number
      x1=byte_sequence_to_bit_sequence(X1);
      x1=x1(2:end);  % do not convert to a positive number
      x2=byte_sequence_to_bit_sequence(X2);
      x2=x2(2:end);  % do not convert to a positive number
      
      x3=binary_subtract(x1,x2);
      % convert result to byte sequence
      m8=mod(length(x3),8);
      if m8>0,
         x3=[repmat(x3(1),1,8-m8),x3];
      end;
      N1=floor(length(x3)/8);
      X3_=uint8(zeros(1,N1));
      for k=0:N1-1,
         X3_(k+1)=uint8(binary_to_uint64(x3(k*8+(1:8))));
      end;
      %******
      
      [X3,X3L]=XXXInt_subtract(X1,X2);
      
      if ~isequal_byte_sequence(X3,X3_),
         warning('X3_~=X3');
         %    else
         %       fprintf('X3_==X3\n');
      end;
      fprintf('X3L=%d\n',X3L);
      
      x1s=repmat('0',1,length(x1));
      x1s(x1)='1';
      fprintf('%s\n',x1s);
      x2s=repmat('0',1,length(x2));
      x2s(x2)='1';
      fprintf('%s\n',x2s);
      x3s=repmat('0',1,length(x3));
      x3s(x3)='1';
      fprintf('%s\n',x3s);
      
      
      i1=int64(binary_to_double(x1));
      i2=int64(binary_to_double(x2));
      i3=int64(binary_to_double(x3));
      
      fprintf('i1=%d; i2=%d; i3=%d, i1-i2=%d\n',i1,i2,i3,i1-i2);
      printf_byte_sequence(X3);
      printf_byte_sequence(X3_);
   otherwise
      error('invalid type');
end;

%%
end

function DECODE1=byte_sequence_rsa_chr_decode(CODE,exponent1,prime1,exponent2,prime2,coefficient,modulus)
   C1=byte_sequence_pow_mod(CODE,exponent1,prime1);
   C2=byte_sequence_pow_mod(CODE,exponent2,prime2);
   if isequal_byte_sequence(C1,C2),
      fprintf('C1==C2\n');
   end;
   while isbigger_byte_sequence(C2,C1),
      C1=add_byte_sequence(C1,prime1);
   end;
   CDIFF=byte_sequence_sub(C1,C2);
   CPROD=prod_byte_sequence(coefficient,CDIFF);
   [Q,CPROD]=divide_byte_sequence(CPROD,prime1);
   CPROD=prod_byte_sequence(CPROD,prime2);
   DECODE1=add_byte_sequence(CPROD,C2);
   [Q,DECODE1]=divide_byte_sequence(DECODE1,modulus);
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


function S=add_byte_sequence(A,B)
A=uint8(A);
B=uint8(B);

a=byte_sequence_to_bit_sequence(A);
b=byte_sequence_to_bit_sequence(B);

s=binary_add_mex(a,b);

% transform bit sequence to byte sequence
S=bit_sequence_to_byte_sequence(s);
end


function S=byte_sequence_sub(A,B)
A=uint8(A);
B=uint8(B);

a=byte_sequence_to_bit_sequence(A);
b=byte_sequence_to_bit_sequence(B);

s=binary_subtract(a,b);

% transform bit sequence to byte sequence
S=bit_sequence_to_byte_sequence(s);
end


function S=byte_sequence_abs_sub(A,B)
A=uint8(A);
B=uint8(B);

a=byte_sequence_to_bit_sequence(A);
b=byte_sequence_to_bit_sequence(B);

s=binary_subtract(a,b);
if s(1),
   s=binary_complement(s);
end;
% transform bit sequence to byte sequence
S=bit_sequence_to_byte_sequence(s);
end


function prod=prod_byte_sequence(seq1,seq2)
seq1=uint16(seq1);
seq2=uint16(seq2);
l1=length(seq1);
l2=length(seq2);
si=uint8(zeros(1,l1+l2));
prod=uint8(zeros(1,l1+l2+1));
for j=l2:-1:1,
   bh=uint16(0);
   for k=l1:-1:1,
      p=seq1(k)*seq2(j)+bh;
      si(1,j+k)=uint8(mod(p,256));      
      bh=floor(double(p)/256);
   end;
   si(1,j)=uint8(bh);
   
   

   bh=uint16(0);
   for k=j+l1:-1:j,       % the full loop is: for k=l1+l2:-1:1,
                 % but it's not necessary to call for k>j+l1 since si(k)==0 for these k 
                 %                             and for k<j 
      p=bh+uint16(prod(k+1))+uint16(si(1,k));
      bh=uint16(0);
      if p>255,
         bh=floor(double(p)/256);
         p=mod(double(p),256);
      end;
      prod(k+1)=uint8(p);
   end;
   
   si(1,j+(1:l1))=0;
   
end;
prod(1)=uint8(bh);

end



function [Q,R]=divide_byte_sequence(N,D)
N=uint8(N);
D=uint8(D);
if all(D == uint8(0))
   error('DivisionByZeroException');
end;
k=find(D>0,1,'first');
D=D(k:end);

if all(N==uint8(0)), % numerator equals zero
   Q=uint8(0);
   R=Q;
   return;
end;

k=find(N>0,1,'first');
N=N(k:end);

n=length(N);
d=length(D);
if d>n,     % denominator is larger than numerator
   Q=uint8(0);
   R=N;
   return;
end;
% transform the byte sequences in a bit sequences:
Nb=byte_sequence_to_bit_sequence(N);
Db=byte_sequence_to_bit_sequence(D);

[Qb,Rb]=binary_divide(Nb,Db);

% transform bit sequence to byte sequence
Q=bit_sequence_to_byte_sequence(Qb);
R=bit_sequence_to_byte_sequence(Rb);
end


function X3=byte_sequence_pow_mod(BASE,EXPO,MODULUS)
base=byte_sequence_to_bit_sequence(BASE);
expo=byte_sequence_to_bit_sequence(EXPO);
modulus=byte_sequence_to_bit_sequence(MODULUS);
x3=binary_pow_mod(base,expo,modulus);
X3=bit_sequence_to_byte_sequence(x3);
end

function Db=byte_sequence_to_bit_sequence(D)
d=length(D);
Db=false(1,d*8+1);
for k=0:d-1,
   bi=dec2bin(D(k+1));
   Lbi=length(bi);
   if Lbi<8,
      bi=[repmat('0',1,8-Lbi),bi];
   end;
   Db(k*8+(1:8)+1)=(uint8(bi)==uint8('1'));
end;
end




function d=uint8_seq_2_double(seq)
b=1;
d=0;
l1=length(seq);
for k=l1:-1:1,
   d=d+double(seq(k))*b;
   b=b*256;
end;
end

function d=uint8_seq_2_uint64(seq)
b=uint64(1);
d=uint64(0);
l1=length(seq);
for k=l1:-1:1,
   d=d+uint64(seq(k))*b;
   b=b*uint64(256);
end;
end


function seq=uint64_2_uint8_seq(ui64)
seq=uint8(zeros(1,8));
i=8;
while ui64>0,
   seq(i)=uint8(mod(ui64,256));
   ui64=ui64-uint64(seq(i));
   ui64=floor(double(ui64)/256);
   i=i-1;
end;
end


function y=binary_pow_mod(base,expo,modulus)
if base(1),
   error('base must be positive');
end;
if expo(1),
   error('exponent must be positive');
end;
if modulus(1),
   error('modulus must be positive');
end;
n=length(expo);
s=base;
y=[false,true];
sti=find(expo,1,'first');
for i=n:-1:sti,
   if expo(i)>0,
%       fprintf('i=%4d, y=[',i);
%       for kj=1:length(y),fprintf('%d ',y(kj)); end;fprintf(']\n');
%       fprintf('i=%4d, s=[',i);
%       for kj=1:length(s),fprintf('%d ',s(kj)); end;fprintf(']\n');
      prod=binary_prod(s,y);
%       fprintf('i=%4d, prod=[',i);
%       for kj=1:length(prod),fprintf('%d ',prod(kj)); end;fprintf(']\n');
%       fprintf('i=%4d, modulus=[',i);
%       for kj=1:length(modulus),fprintf('%d ',modulus(kj)); end;fprintf(']\n');
      [q,y]=binary_divide(prod,modulus);
%       fprintf('i=%4d, y=[',i);
%       for kj=1:length(y),fprintf('%d ',y(kj)); end;fprintf(']\n');
   end;
   [q,s]=binary_divide(binary_prod(s,s),modulus);
end;

end

function y=binary_prod(a,b)
if a(1),
   error('a must be positive');
end;
if b(1),
   error('b must be positive');
end;
la=length(a);
lb=length(b);
y=false(1,la+lb);
s=[false(1,lb),a];
for i=lb:-1:1,
   if b(i),
      y=binary_add_mex(y,s);
   end;
   s((1:la)+i-1)=a;
   s(la+i)=false;
end;
y=y(find(y,1,'first'):end);
y=[false,y];
end

function D=bit_sequence_to_byte_sequence(Db)
if Db(1),
   error('bit sequence to be transformed in byte sequence must be positive!');
end;
if ~any(Db),
   D=uint8(0);
   return;
end;
Db=Db(find(Db,1,'first')-1:end);
d=length(Db);

N=ceil(d/8);
if d<N*8,
   Db=[false(1,N*8-d),Db];
end;

D=uint8(zeros(1,N));
for k=0:N-1,
   D(k+1)=uint8(binary_to_uint64(Db(k*8+(1:8))));
end;
end

function d=binary_to_double(seq)
isneg=seq(1);
if isneg,
   seq=binary_complement(seq);
end;
b=1;
d=0;
l1=length(seq);
for k=l1:-1:1,
   d=d+double(seq(k))*b;
   b=b*2;
end;
if isneg,
   d=-d;
end;
end

function d=binary_to_uint64(seq)
b=uint64(1);
d=uint64(0);
l1=length(seq);
for k=l1:-1:1,
   d=d+uint64(seq(k))*b;
   b=b*uint64(2);
end;
end



function seq=uint_to_binary(ui,nbit)
ui64=uint64(ui);
seq=false(1,nbit+1);
ui64_1=uint64(1);
i=nbit+1;
while ui64>0,
   seq(i)=logical(bitand(ui64,ui64_1));
   ui64=ui64-uint64(seq(i));
   ui64=bitshift(ui64,-1);
   i=i-1;
end;
end

function a=inc_length_signed_binary(a,inc_n)
if inc_n>0,
   a=[repmat(a(1),1,inc_n),a];
end;

end

function s=binary_add____(a,b)
% persistent bit_res
% persistent carry_res
% persistent ind_in1
% persistent ind_in2
% persistent ind_carry_in

% if isempty(bit_res),
%    bit_res=false(2,2,2);
%    carry_res=false(2,2,2);
%    bit_res(1,1,:)=[false,true]; carry_res(1,1,:)=[false,false];
%    bit_res(1,2,:)=[true,false]; carry_res(1,2,:)=[false,true];
%    bit_res(2,1,:)=[true,false]; carry_res(2,1,:)=[false,true];
%    bit_res(2,2,:)=[false,true]; carry_res(2,2,:)=[true,true];
% end;

%the first bit is the sign bit



% make length equal 1+max length to avoid overrun:
n=length(a)+1;
nb=length(b)+1;
if n>nb,
   b=[repmat(b(1),1,n-nb+1),b];
   a=[a(1),a];
elseif n<nb,
   a=[repmat(a(1),1,nb-n+1),a];
   b=[b(1),b];
   n=nb;
else
   a=[a(1),a];
   b=[b(1),b];
end;

     %   in1, in2, carr_in



s=false(1,n);
carry=false;
for k=n:-1:1,
%    ind_in1=[~a(k),a(k)];
%    ind_in2=[~b(k),b(k)];
%    ind_carry_in=[~carry,carry];
%    carry=carry_res(ind_in1,ind_in2,ind_carry_in);
%    s(k)=bit_res(ind_in1,ind_in2,ind_carry_in);
   s(k) = ~a(k) && ~b(k) && carry || ...
      ~a(k) && b(k) && ~carry || ...
      a(k) && ~b(k) && ~carry || ...
      a(k) && b(k) && carry;
   carry = ~a(k) && b(k) && carry || ...
      a(k) && ~b(k) && carry || ...
      a(k) && b(k) && ~carry || ...
      a(k) && b(k) && carry;
   
%    si=uint8(a(k))+uint8(b(k))+uint8(carry);
%    carry=(si>uint8(1));
%    s(k)=mod(si,2);
end;

% reduce bit length if possible
if s(2)==s(1),
   s=s(2:end);
end;
end






function s=binary_complement(a)
n=length(a);
if ~any(a),
   s=a;
   return;
end;
s=~a;
b=false(1,n);
b(n)=true;
s=binary_add_mex(s,b);
end

function s=binary_subtract(a,b)
% computes a-b for two logical arrays
bc=binary_complement(b);
s=binary_add_mex(a,bc);
end

function [Qb,Rb]=binary_divide(Nb,Db)
if ~any(Db),
   error('division by zero');
end;
if ~any(Nb),
   Qb=false(1,2);
   Rb=false(1,2);
   return;
end;

isn=(Nb(1) && ~Db(1)) || (~Nb(1) && Db(1));
if Nb(1),
   Nb=binary_complement(Nb);
   Nisneg=true;
else
   Nisneg=false;
end;
if Db(1),
   Db=binary_complement(Db);
end;

Nb=Nb(find(Nb,1,'first'):end);
Db=Db(find(Db,1,'first'):end);
Nb=[false,Nb];
Db=[false,Db];

% from here on, Qb, Rb are positive!!!!
nb=length(Nb);
db=length(Db);
if db==2,     % division by +-1
   Qb=Nb;
   if isn,
      Qb=binary_complement(Qb);
   end;
   Rb=false(1,nb);
   return;
end;

%** extend the length of the shorter sequences to that of the longer one:
if nb>db,
   Db=[false(1,nb-db),Db];
elseif nb<db,
   Nb=[false(1,db-nb),Nb];
end;
n=max(nb,db);

Db_c=binary_complement(Db);


Qb=Nb;  %                 -- initialize quotient and remainder to zero
Rb=false(1,n);

for i = 1:n,   %     -- where n is number of bits in N
%    fprintf('step %d: [Q,R]=[',i);
%    for bi=1:length(Rb), fprintf('%d ',Rb(bi));end;
%    for bi=1:length(Qb), fprintf('%d ',Qb(bi));end;
%    fprintf(']\n');
   
   Rb(1:n-1)=Rb(2:n);  %     -- left-shift R by 1 bit
   Rb(n)=Qb(1);
   Qb(1:n-1)=Qb(2:n);Qb(n)=false; % -- left shift Q
   x=binary_add_mex(Db_c,Rb);
   if ~x(1),
      Qb(n)=true;
      Rb=x;
   end;
end;


if isn,
   Qb=binary_complement(Qb);
end;
if Nisneg,
   Rb=binary_complement(Rb);
end;

end


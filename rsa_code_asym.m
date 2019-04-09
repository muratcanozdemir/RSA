function outname=rsa_code_asym(filename,n,e,d);
if nargin<2,
   n=1;
end;
if abs(n)==1,
   if n==1,
      d=[];
   else
      d=2033849;
   end;
   n=2868847; 
   e=1434425;
elseif nargin<4,
   d=[];
end;

dirn=[getenv('systemroot'),'\..\..\..\temp'];
dirn=[dirn(1:3),'temp'];
if exist(dirn)~=7,
   mkdir(dirn);
end;
if isempty(d),
   outname=[dirn,'\tmptmp.code'];
   encode_file(filename,outname,n,e);
else
   outname=[dirn,'\tmptmp.decode'];
   decode_file(filename,outname,n,e,d);
end;
return;


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

return;

function bi=binary_convert(x,base,ndigits);
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
return;


function x=binary_reconvert(bi,base);
x=0;
f=1;
L=length(bi);
for i=0:L-1,
   x=x+double(bi(L-i))*f;
   f=f*base;
end;
return;

function ds=n_bit_coding(d,m,n,linelength);
%d: uint vector with m bit resolution
% ds: coded vector with n bit resolution (returned as double vector)
% for n<7, ds returns a character matrix
d=double(d);
c=uint8(zeros(length(d),m));
for i=1:length(d),
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

if n<7,
   codes=[(48:57),(97:122),(65:90),43,45];
   k=ceil(length(ds)/linelength);
   dc=zeros(k*linelength,1);
   dc(1:length(ds))=codes(ds+1);
   dc=reshape(dc,linelength,k)';
   if k*linelength>length(ds),
      dc(k,linelength-k*linelength+length(ds)+1:linelength)=32;
   end;
   ds=char(dc);
end;
return;

function ds=n_bit_decoding(d,n,m);
if n<7,
   codes=[(48:57),(97:122),(65:90),43,45];
   d=d';
   d=d(:);
   d=char(d');
   
   ind=strfind(d,char([13 10]));
   if isempty(ind)==0,
      ind=union(ind,ind+1);
      d=d(setdiff((1:length(d)),ind));
   end;
   ind=strfind(d,char(10));
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind));
   end;
   ind=strfind(d,' ');
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind));
   end;
   ind=strfind(d,char(9));
   if isempty(ind)==0,
      d=d(setdiff((1:length(d)),ind));
   end;
   d=double(d);
   for i=1:length(d),
      d(i)=find(codes==d(i),1,'first')-1;
   end;
else
   d=double(d(:));
end;


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
for i=1:k,
   ds(i)=binary_reconvert(cs(i,m:-1:1),2);
end;
return;


function o=filter_coding(data,n,e);
[a,b]=mk_filtpars(n,e);
o=z_filter(b,a,data);
return;

function o=filter_decoding(data,n,e);
[a,b]=mk_filtpars(n,e);
o=z_filter(a,b,data);
return;

function [a,b]=mk_filtpars(n,e);
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
return;

function a=blowup_n(n,e,p2);
xs=n;
x=mod(xs,round(2^16));
for k=1:p2,
   xs=n_bit_coding(x,16,8)+2^5;

   for i=1:length(xs),
      xs(i)=mod_power(xs(i),e,n);
   end;
   x=mod(xs,round(2^16));
end;
a=x;
return;




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
return;




function decode_file(filename,outname,n,e,d);

fid=fopen(filename,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid);
fseek(fid,0,'bof');
data=fread(fid);
data=char(data);
fclose(fid);

data=n_bit_decoding(data,6,22);

bi=binary_convert(d,2,32);
sti=find(bi>0,1,'first');
bi=bi(sti:end);

for i=1:length(data),
   data(i)=mod_power(data(i),bi,n);
end;
data=data-237;
fid=fopen(outname,'wb');
fwrite(fid,data,'uint16');
fclose(fid);

fid=fopen(outname,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid)/8;
fseek(fid,0,'bof');
data=fread(fid,cnt,'double');
fclose(fid);

data=filter_decoding(data,n,e);
data=round(data);

fid=fopen(outname,'wb');
fwrite(fid,data,'uint8');
fclose(fid);

return;



function encode_file(filename,outname,n,e);


fid=fopen(filename,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid);
fseek(fid,0,'bof');
data=fread(fid);
fclose(fid);

y=filter_coding(data,n,e);


fid=fopen(outname,'wb');
fwrite(fid,y,'double');
fclose(fid);

fid=fopen(outname,'rb');
fseek(fid,0,'eof');
cnt=ftell(fid)/2;
fseek(fid,0,'bof');
data=fread(fid,cnt,'uint16');
fclose(fid);

data=double(data)+237;

bi=binary_convert(e,2,32);
sti=find(bi>0,1,'first');
bi=bi(sti:end);
for i=1:length(data),
   data(i)=mod_power(data(i),bi,n);
end;

ds=n_bit_coding(data,22,6,20);

ds=[ds,char(repmat([13 10],size(ds,1),1))];
ds=double(ds);
fid=fopen(outname,'wb');
fwrite(fid,ds','char');
fclose(fid);


return;

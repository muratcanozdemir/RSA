function rsa_demo();

% t=(0:65535);
% ds=n_bit_coding(t,16,6,50)
% t1=n_bit_decoding(ds,6,16)';
% max(abs(t-t1))
% return;

n=[];
%[n,e,d]=rsa_generate_key;

n=2868847; e=1434425; d=2033849;
%n=3382121; e=1691063; d=3284231;
%n=3324767; e=1662383; d=791567;
%n=3003289; e=1501645; d=1498181;
%n=3075991; e=1537995; d=2652387;

filename='c:\users\eggert\ex\bangbang.exe';
filename='c:\temp\nachricht.txt';
filename1='c:\temp\tmptmp.ccd';
tic
if isempty(n),
   outfile=rsa_code(filename,1);
else
   outfile=rsa_code(filename,n,e);
end;
toc
tic
if isempty(n),
   rsa_code(outfile,-1);
else
   rsa_code(outfile,n,e,d);
end;
toc

return;


for m=0:n,
   c=mod_power(m,e,n);
   
   m1=mod_power(c,d,n);
   if mod(m,10000)==0,
      disp(sprintf('%d %d %d ',m,c,m1));
      pause(0.01);
   end;
   if m~=m1,
      error(sprintf('error: n: %d, m: %d, c: %d, m1: %d ',n,m,c,m1));
   end;
      
end;   
   
return;

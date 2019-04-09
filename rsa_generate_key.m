function [n,e,d]=rsa_generate_key();

R=50;
LP=primes(2000);
LP=LP(end-R+1:end);
p_i=floor(rand(1,1)*R)+1;
p=LP(p_i);
LP=LP(setdiff((1:R),p_i));
q_i=floor(rand(1,1)*(R-1))+1;
q=LP(q_i);


n=p*q;  % 2^21<n<2^22
phi=(q-1)*(p-1);
e=floor(n/2);
while 1,
   if gcd(e,phi)==1 | e>=phi,
      break;
   end;
   e=e+1;
end;
if e>=phi,
   error('generation of e failed!');
end;


d=floor(rand(1,1)*phi);
k=0;
while 1,
   if mod(e*d,phi)==1 | k>=phi,
      break;
   end;
   k=k+1;
   d=mod(d+1,phi);
end;
if d>=phi,
   error('generation of d failed!');
end;
%disp(sprintf('n=%d; e=%d; d=%d;',n,e,d));
return;

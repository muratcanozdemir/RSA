function res=rsa_code(filename,n,E,action,outname,start_ptr)
%#codegen
%*** this is a symmetric version of rsa_code_asym
%***  filename: input filename
%***         n: basis
%***         E: exponent
%***    action: 'decode'  : do decoding
%***           'encode': do encoding  (default)
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
if nargin<2 || isempty(n),
   n=[];
end;
if nargin<3 || isempty(E),
   E=[];
end;
if nargin<4 || isempty(action),
   action='';
end;
if nargin<5 || isempty(outname),
   outname='';
end;
if nargin<6 || isempty(start_ptr),
   start_ptr=0;
end;

mversion=sscanf(version('-release'),'%d%c');
if mversion(1)>=2011,
   if exist('rsa_code_matlab2011b_mex.mexw64','file')==3,
      res=rsa_code_matlab2011b_mex(filename,n,E,action,outname,start_ptr);
   else
      res=rsa_code_matlab2011b(filename,n,E,action,outname,start_ptr);
   end;
else
   res=rsa_code_matlab2007a(filename,n,E,action,outname,start_ptr);
end;
end

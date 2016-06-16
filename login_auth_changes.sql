DECLARE

	result boolean :=FALSE;
BEGIN

	result:=AUTHENTICATION_PKG.authenticate_user(p_user_name_in => :P101_USERNAME,p_password_in => :P101_PASSWORD);
	
	if (result=TRUE)
	then
	
		wwv_flow_custom_auth_std.post_login
		(P_UNAME => :P101_USERNAME,
		P_PASSWORD => :P101_PASSWORD,
		P_SESSION_ID => v('APP_SESSION'),
		P_FLOW_PAGE => :APP_ID||':1');
	else
		owa_util.redirect_url('f?p=&APP_ID.:101:&SESSION.');
	end if;

END;
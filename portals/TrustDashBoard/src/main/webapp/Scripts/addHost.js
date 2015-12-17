var oemInfo = [];
var isVmware = 0;  // 0 == TA, 1 == Citrix

$(function() {
	$('#mainAddHostContainer').prepend(disabledDiv);
        $('#updateHostButton').hide();
	sendJSONAjaxRequest(false, 'getData/getAllOemInfo.html', null, fnGetAllOemInfoSuccess, null);
	/*
	 * Function to check validation as input loose focus.
	 */

	$('#MainContent_tbHostName').blur(function() {
		fnTestValidation('MainContent_tbHostName',normalReg);
	});
	$('#MainContent_tbHostPort').blur(function() {
		if (isVmware == 'false') {
			$('.portNoError').each(function() {
				$(this).remove();
			});
			if (!regPortNo.test($('#MainContent_tbHostPort').val())) {
				$('#MainContent_tbHostPort').parent().append('<span class="errorMessage validationErrorDiv portNoError" style="float:none">only Numeric values are allowed.</span>');
				return false;
			}
			if ($('#MainContent_tbHostPort').val().length > 4 ) {
				$('#MainContent_tbHostPort').parent().append('<span class="errorMessage validationErrorDiv portNoError" style="float:none">Port NO length should not be greater 4.</span>');
				return false;
			}
		}
	});
	$('#MainContent_tbHostIP').blur(function() {
		if (isVmware == 'false') {
			fnTestValidation('MainContent_tbHostIP',regIPAddress);
		}
	});
});

function fnGetAllOemInfoSuccess(responseJSON) {
	if (responseJSON.result) {
		oemInfo = responseJSON.oemInfo;
		var options = "";
		for ( var str in oemInfo) {
			options +='<option value="'+str+'">'+str+'</option>';
		}
		$('#MainContent_ddlOEM').html(options);
		sendJSONAjaxRequest(false, 'getData/getOSVMMInfo.html', null, fnGetOSVMMInfoSuccess, null);
		fnChangeOEMVender();
	}else {
		$('#disabledDiv').remove();
		$('#mleMessage').html('<div class="errorMessage">'+getHTMLEscapedMessage(responseJSON.message)+'</div>');
               	$('#addHostButton').attr('disabled','false');

	}
}


function fnGetOSVMMInfoSuccess(responsJSON) {
	if (responsJSON.result) {
		var options = "";
		for ( var str in responsJSON.osInfo) {
			options +='<option isvmware="'+responsJSON.osInfo[str]+'" value="'+str+'">'+str+'</option>';
		}
                if (options != "") {
                    $('#MainContent_LstVmm').html(options);
                    $('#MainContent_LstVmm option:eq(0)').attr('selected', 'selected');
                    $('#MainContent_LstVmm').trigger('change');
                } else {
                    var errorMsg = "No VMM MLEs are configured in the system."
                    $('#mleMessage').html('<div class="errorMessage">'+ errorMsg +'</div>');
                    $('#addHostButton').attr('disabled','false');
                }
	}else {
		$('#mleMessage').html('<div class="errorMessage">'+getHTMLEscapedMessage(responsJSON.message)+'</div>');
	}
	if (isAddHostPage) {
		$('#disabledDiv').remove();
	}else {
		sendJSONAjaxRequest(false, 'getData/getInfoForHostID.html',"hostName="+selectedHostID, fnFillAddHostPageDataForEdit, null);
	}
}

function fnChangeOEMVender() {
	var selected = $('#MainContent_ddlOEM').val();
	for ( var oem in oemInfo) {
		if (oem == selected) {
			var options = "";
			for ( var name in oemInfo[oem]) {
				for ( var val in oemInfo[oem][name]) {
					options +='<option biosName="'+val+'" biosVer="'+oemInfo[oem][name][val]+'">'+val+' '+oemInfo[oem][name][val]+'</option>';
				}
			}
			$('#MainContent_LstBIOS').html(options);
		}
	}
}

function SetRequired(element) {
    var selected = $(element).val();
    
	$(element).find('option').each(function() {
		if ($(this).text() == selected) {
			type = $(this).attr('value');  // 'isvmware'
		}
	});
    
    if (type.toString().toLowerCase().indexOf("vmware") != -1) {  
		isVmware = 1;
	}else if(type.toString().toLowerCase().indexOf("xenserver") != -1) {
       isVmware = 2;
	}else{
        isVmware= 0;
    }
    
	$('.requiredOne').each(function() {
		$(this).remove();
	});
	var reqStr = '<span id="requiredFiled" class="requiredOne" style="color:red;">*  </span>';
                        $('#hostPortDisplayDiv').show();
                        $('#MainContent_tbHostIP').parent().append(reqStr);
                        $('#MainContent_tbHostPort').parent().append(reqStr);
    if(isVmware == 2) {  // Citrix
        $('#hostPortDisplayDiv').show();
                //$('#MainContent_tbHostIP').parent().append(reqStr);
				$('#MainContent_tbHostPort').parent().append(reqStr);
                $('#vcenterStringElement').find('input').each(function() {
                    $(this).parent().find('.validationErrorDiv').remove();
                });
                $('#vcenterStringElement').hide(); 
                
                $('#citrixStringElement').find('input').each(function() {
                    $(this).parent().append(reqStr);
                });
                $('#citrixStringElement').show();
                $('#MainContent_tbHostPort').val("443");
    }else { // TA
        $('#hostPortDisplayDiv').show();
		//$('#MainContent_tbHostIP').parent().append(reqStr);
		$('#MainContent_tbHostPort').parent().append(reqStr);
		$('#vcenterStringElement').find('input').each(function() {
			$(this).parent().find('.validationErrorDiv').remove();
		});
		$('#vcenterStringElement').hide();
		$('#citrixStringElement').hide();
                $('#MainContent_tbHostPort').val("9999");
    }
  
}

function hostDataVoObbject(hostId,hostName,hostIPAddress,hostPort,hostDescription,biosName,biosBuildNo,vmmName,vmmBuildNo,updatedOn,emailAddress,location,oemName) {
	this.hostId = hostId;
	this.hostName = hostName;
	this.hostIPAddress = hostIPAddress;
	this.hostPort = hostPort;
	this.hostDescription = hostDescription;
	this.biosName = biosName;
	this.biosBuildNo = biosBuildNo;
	this.vmmName = vmmName;
	this.vmmBuildNo = vmmBuildNo;
	this.updatedOn =updatedOn;
	this.emailAddress =emailAddress;
	this.location =location;
	this.oemName =oemName;
}

function chechAddHostValidation() {
	$('.validationErrorDiv').each(function() {
		$(this).remove();
	});	

	var valid1 = fnTestValidation('MainContent_tbHostName',normalReg);
	var valid2  = true;
	var valid3 = true;
	var valid4 = true;
                        valid2 = fnTestValidation('MainContent_tbHostPort',normalReg);
                        valid3 = fnTestValidation('MainContent_tbHostIP',normalReg);
                        valid4 = isValidIPAddress('MainContent_tbHostIP');
                        if (!valid4){$('#MainContent_tbHostIP').parent().append('<span class="errorMessage validationErrorDiv" style="float:none">Enter valid IP address.</span>');
                        valid =false;
                        return false;}
			
                        if($('#MainContent_tbDesc').val()){

                                if(!(fnValidateDescription('MainContent_tbDesc')))
                                {$('#MainContent_tbDesc').parent().append('<span class="errorMessage validationErrorDiv" style="float:none">Special characters % and & are not allowed.</span>');
                                return false;
                                }
                        }
                if($('#MainContent_tbEmailAddress').val()){
                        if(!(fnvalidateEmailAddress('MainContent_tbEmailAddress')))
                        {$('#MainContent_tbEmailAddress').parent().append('<span class="errorMessage validationErrorDiv" style="float:none">Enter a valid email address.</span>');
                        return false;}

        }
        
	if (valid1 && valid2 && valid3) {
		
		if(isVmware == 'false'){
			if (!regPortNo.test($('#MainContent_tbHostPort').val())) {
				$('#MainContent_tbHostPort').parent().append('<span class="errorMessage validationErrorDiv" style="float:none">Only numeric values are allowed.</span>');
				return false;
			}
			if ($('#MainContent_tbHostPort').val().length > 5 ) {
				$('#MainContent_tbHostPort').parent().append('<span class="errorMessage validationErrorDiv" style="float:none">Length should not be greater 5.</span>');
				return false;
			}
		}
		return true;
	}else {
		return false;
	}
}

function fnGetNewHostData() {
	var hostVo = new hostDataVoObbject();
	hostVo.hostName = $.trim($('#MainContent_tbHostName').val());
	hostVo.hostDescription = $('#MainContent_tbDesc').val();
	hostVo.biosName = $('#MainContent_LstBIOS option:selected').attr('biosname');
	hostVo.biosBuildNo = $('#MainContent_LstBIOS option:selected').attr('biosver');
	var vmm = $('#MainContent_LstVmm').val().split(':');
        //We re-insert : to separate OS and its version
	hostVo.vmmName = vmm[0]+":"+vmm[1];
	hostVo.vmmBuildNo = vmm[2];
	hostVo.emailAddress = $('#MainContent_tbEmailAddress').val();
	hostVo.oemName = $('#MainContent_ddlOEM').val();
		
	hostVo.hostIPAddress = $.trim($('#MainContent_tbHostIP').val());
    hostVo.hostPort =$.trim($('#MainContent_tbHostPort').val());
	if(isVmware == 2) {
        // itrix:https://xenserver:port;username;password
        hostVo.vCenterDetails = "citrix:https://"+$('#MainContent_tbHostName').val()+":"+$('#MainContent_tbHostPort').val()+
                                             "/;"+$('#MainContent_tbVcitrixLoginId').val()+";"+$('#MainContent_tbVcitrixPass').val();
        
    }
	//setting unwanted values to null or default
	hostVo.location = null;
	hostVo.updatedOn = null;
	return hostVo;
}

function addNewHost() {
	if (chechAddHostValidation()) {
		if (confirm("Are you Sure you want to Add this Host ?")) {
			var dataToSend = fnGetNewHostData();
			dataToSend.hostId = null;
			dataToSend = $.toJSON(dataToSend);
			$('#mainAddHostContainer').prepend(disabledDiv);
			$('#mleMessage').html('');
			sendJSONAjaxRequest(false, 'getData/saveNewHostInfo.html', "hostObject="+(dataToSend)+"&newhost=true", fnSaveNewHostInfoSuccess, null,"New Host has been successfully Added.");
		}
	}
}

function fnSaveNewHostInfoSuccess(response,messageToDisplay) {
	$('#disabledDiv').remove();
	if (response.result) {
		clearAllFiled('mainAddHostContainer');
		$('#mleMessage').html('<div class="successMessage">'+messageToDisplay+'</div>');
	}else {
		$('#mleMessage').html('<div class="errorMessage">'+getHTMLEscapedMessage(response.message)+'</div>');
	}
}



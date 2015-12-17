/**
* function to edit Mle Page ... 
*/

var isVMM = true;
var listOfmanifest = [];

//called on load
$(function() {
	$('#mainEditMleDisplayDiv').prepend(disabledDiv);
	sendJSONAjaxRequest(false, 'getData/getViewMle.html', null, fnUpdateEditMleTable, null);
});

/*method to display edit table*/
function fnUpdateEditMleTable(responseJSON) {
	$('#disabledDiv').remove();
	if (responseJSON.result) {
		$('#mainTableDivEditMle').show();
		fuCreateEditMleTable(responseJSON.MLEDataVo);
		applyPagination('editMlePaginationDiv',responseJSON.noOfPages,fngetMleNextPageForEdit,1);
	}else {
		$('#messageSpace').html(responseJSON.message);
	}
}

/*function to get the value for give page no*/
function fngetMleNextPageForEdit(pageNo) {
	$('#mainEditMleDisplayDiv').prepend(disabledDiv);
	sendJSONAjaxRequest(false, 'getData/getViewMleForPageNo.html', "pageNo="+pageNo, fnUpdateEditMleTableForPage, null);
}

function fnUpdateEditMleTableForPage(responseJSON) {
	$('#disabledDiv').remove();
	if (responseJSON.result) {
		fuCreateEditMleTable(responseJSON.MLEDataVo);
	}else {
		$('#messageSpace').html(responseJSON.message);
	}
}


/*Method to create dynamic edit table for MLE*/
function fuCreateEditMleTable(mleData) {
	var str = "";
	$('#editMleContentDiv table tbody').html("");
	for ( var items in mleData) {
		var classValue = null; 
		if(items % 2 === 0){classValue='oddRow';}else{classValue='evenRow';}
		str+='<tr class="'+classValue+'">'+
		'<td class="row1"><a href="javascript:;" onclick="fnEditMleInfo(this)"> Edit </a><span> | </span><a href="javascript:;" onclick="fnDeleteMleInfo(this)"> Delete </a></td>'+
		'<td class="rowr3" style="word-wrap: break-word;max-width:170px;" name="mleName">'+mleData[items].mleName+'</td>'+
		'<td class="row2" name="mleVersion">'+mleData[items].mleVersion+'</td>'+
		'<td class="rowr3" name="attestation_Type">'+mleData[items].attestation_Type+'</td>';
		var val1 = mleData[items].manifestList == undefined ? ' ' : mleData[items].manifestList;
		
		 //str+='<td class="rowr7" name="manifestList">'+val1+'&nbsp;</td>'+
		str+='<td class="row4" name="mleType">'+mleData[items].mleType+'</td>';
		val1 = mleData[items].osName == undefined ? ' ' : mleData[items].osName;
		var val2 = mleData[items].osVersion == undefined ? ' ' : mleData[items].osVersion;
		str+='<td class="rowr4" name="osName" version="'+val2+'" osName="'+val1+'">'+val1 +' '+val2+'&nbsp;</td>';
		val1 = mleData[items].oemName == undefined ? ' ' : mleData[items].oemName;
		str+='<td class="rowr2" name="oemName">'+val1+'&nbsp;</td>';
		val1 = mleData[items].mleDescription == undefined ? ' ' : mleData[items].mleDescription;
		str+='<td class="rowr3"  style="word-wrap: break-word;max-width:170px;"name="mleDescription">'+val1+'&nbsp;</td></tr>';
	}
	$('#editMleContentDiv table tbody').html(str);
}

function fnEditMleInfo(element) {
	$('#messageSpace').html('');
	var data = [] ;
    var row = $(element).parent().parent();
    $(row).find("td:not(:first-child)").each(function(){
        var val = $.trim($(this).text());
        var name = $.trim($(this).attr('name'));
        data[name]=val;
    });
   	data["osVersion"]=$(row).find("td:eq(5)").attr('version');
   	data["osName"]=$(row).find("td:eq(5)").attr('osName');
    setLoadImage('mainContainer');
	sendHTMLAjaxRequest(false, 'getView/getAddMLEPage.html', null, fnEditMleData, null,data);
}

function fnGetMleDataForEdit(data) {
	var dataToSend = "mleName="+data.mleName+"&mleVersion="+data.mleVersion+"&mleType="+data.mleType+"&attestation_Type="+data.attestation_Type;
	if (data.mleType == "VMM") {
		isVMM = true;
		dataToSend+="&osName="+data.osName;
		dataToSend+="&osVersion="+data.osVersion;
		updateMlePageForVMM();
		$('#MainContent_ddlMLEType').html('<option value="VMM" selected="selected">VMM</option>');
	}else{
		isVMM = false;
		dataToSend+="&oemName="+data.oemName;
		$('#MainContent_ddlMLEType').html('<option value="BIOS" selected="selected">BIOS</option>');
		updateMlePageForBIOS();
	}
	return dataToSend;
}

function fnEditMleData(response,data) {
	$('#mainContainer').html(response);
        $('#mainDataTableMle').prepend(disabledDiv);
	var dataToSend = fnGetMleDataForEdit(data);
	sendJSONAjaxRequest(false, 'getData/viewSingleMLEData.html', dataToSend, fnEditMleDataSuccess , null,dataToSend);
}

function fnEditMleDataSuccess(responseJson,dataToSend) {
	if (responseJson.result) {
                var mleSourceHostName = responseJson.mleSource;
		var response = responseJson.dataVo;
		hostNameList = [];
		hostNameList[0] = response;
		$('#disabledDiv').remove();
		
		var host = isVMM ? response.osName+" "+response.osVersion : response.oemName;
		
		$('#MainContent_ddlMLEType').attr('disabled','disabled');
		$('#MainContent_ddlHostOs').html('<option value="'+host+'" >'+host+'</option>');
		$('#MainContent_ddlHostOs').attr('disabled','disabled');
		
		$('#mleTypeNameValue').html('<input id="MainContent_ddlMLEName" type="text" class="inputs textBox_Border" disabled="disabled" value="'+response.mleName+'" >');
		
		$('#MainContent_tbVersion').attr('value',response.mleVersion);
		$('#MainContent_tbVersion').attr('disabled','disabled');
		
		$('#MainContent_ddlAttestationType').html('<option selected="selected">'+response.attestation_Type+'</option>');
		$('#MainContent_tbDesc').val(response.mleDescription);
		$('#MainContent_tbMleSourceHost').val(mleSourceHostName);
		
                                                for ( var pcr in response.manifestList) {
                                                        fnToggelRegisterValue(true,'MainContent_tb'+response.manifestList[pcr].Name);
                                                        $('#MainContent_check'+response.manifestList[pcr].Name).attr('checked','checked');
                                                        $('#MainContent_tb'+response.manifestList[pcr].Name).attr('value',response.manifestList[pcr].Value);
                                                }
                
                                                // Bug: 565 : For some reason dynamically changing the attribute of the button to call the UpdateMLE function 
                                                // is not working. As a workaround, we will create 2 buttons to start with, one button for adding the MLE and 
                                                // the second one for updating. If the Add MLE page, we will hide the "Update MLE" button and vice versa.

                                //              $('#addMleButton').attr("value", "Update MLE");
                                //		$('#addMleButton').attr("onclick", "updateMleInfo()");
                
	}else {
		$('#disabledDiv').remove();
		$('#mleMessage').html('<div class="errorMessage">'+responseJson.message+'</div>');
	}
}


function updateMleInfo() {
	var dataToSent = fnGetMleData(false);
	if (dataToSent != "") {
		if (confirm("Are you Sure you want to update this MLE ?")) {
			$('#mainDataTableMle').prepend(disabledDiv);
			sendJSONAjaxRequest(false, 'getData/getAddMle.html', "mleObject="+dataToSent+"&newMle=false", updateMleSuccess, null);
		}
	}
}

function updateMleSuccess(response) {
$('#disabledDiv').remove();
	if (response.result) {
		$('#mleMessage').html('<div class="successMessage">MLE has been successfully updated.</div>');
	}else{
		$('#mleMessage').html('<div class="errorMessage">'+response.message+'</div>');
	}
}


function fnDeleteMleInfo(element) {
	if (confirm("Are you sure you want to delete this MLE ?")) {
		$('#messageSpace').html('');
		var data = [] ;
	    var row = $(element).parent().parent();
	    row.find("td:not(:first-child)").each(function(){
	        var val = $.trim($(this).text());
	        var name = $(this).attr('name');
	        data[name]=val;
	    });
	   	data["osVersion"]=row.find("td:eq(5)").attr('version');
	   	data["osName"]=row.find("td:eq(5)").attr('osName');
	   	var mleName = $.trim(row.find("td:eq(1)").text()); 
		var dataToSend = fnGetMleDataForDelete(data);
		$('#mainTableDivEditMle').prepend(disabledDiv);
		sendJSONAjaxRequest(false, 'getData/deleteMLEData.html', dataToSend+"&selectedPageNo="+selectedPageNo, fnDeleteMleInfoSuccess , null,element,mleName);
	}
}

function fnGetMleDataForDelete(data) {
	var dataToSend = "mleName="+data.mleName+"&mleVersion="+data.mleVersion+"&mleType="+data.mleType+"&attestation_Type="+data.attestation_Type;
	if (data.mleType == "VMM") {
		isVMM = true;
		dataToSend+="&osName="+data.osName;
		dataToSend+="&osVersion="+data.osVersion;
	}else{
		isVMM = false;
		dataToSend+="&oemName="+data.oemName;
	}
	return dataToSend;
}

function fnDeleteMleInfoSuccess(response,element,mleName) {
	$('#disabledDiv').remove();
	if (response.result) {
		fuCreateEditMleTable(response.MLEDataVo);
                $('#messageSpace').html('<div class="successMessage">* MLE "'+mleName+'" has been successfully deleted.</div>');
		if (selectedPageNo > (response.noOfPages)) {
			selectedPageNo = response.noOfPages;
		}
		applyPagination('editMlePaginationDiv',response.noOfPages,fngetMleNextPageForEdit,selectedPageNo);		
	}else{
		$('#messageSpace').html('<div class="errorMessage">'+response.message+'</div>');
	}
}
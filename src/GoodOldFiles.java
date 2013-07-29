package org.zaproxy.zap.extension.GoodOldFiles;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;

import java.awt.CardLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.FileStore;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Random;
import java.util.Vector;
import java.util.regex.Pattern;

import javax.swing.*;

import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.log4j.Logger;
import org.apache.tools.ant.types.Environment;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractDefaultFilePlugin;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.db.TableSession;
import org.parosproxy.paros.db.TableSessionUrl;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.OptionsDialog;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.bruteforce.BruteForceListenner;
import org.zaproxy.zap.extension.bruteforce.DirBusterManager;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

import com.sittinglittleduck.DirBuster.BaseCase;
import com.sittinglittleduck.DirBuster.ExtToCheck;
import com.sittinglittleduck.DirBuster.GenBaseCase;

public class GoodOldFiles extends AbstractAppPlugin implements BruteForceListenner {

	class ObsoleteFilesParam extends AbstractParam
	{
		private String badResponseKey;
		private int threadsNum;
		public ArrayList<String> blacklistExtensions;
		public ArrayList<String> listExtensions;
		public ArrayList<String> prefixesForFiles;
		public ArrayList<String> suffixesForFiles;
		private long timeout;
		private boolean caseSensitve;
		private int suffixCounter;
		
		public ArrayList<String> getListExtensions() {
			return listExtensions;
		}

		public void setListExtensions(ArrayList<String> listExtensions) {
			this.listExtensions = listExtensions;
		}

		public ObsoleteFilesParam()
		{
			this.threadsNum = 50;
			this.blacklistExtensions = new ArrayList<String>(Arrays.asList(new String[]{"gif","jpg","jpeg","bmp","css","js","doc","docx","pdf","xls","xlsx","xlsm","docm","ppt","pptx","pps","bmp","png","css","xml"}));
			this.listExtensions = new ArrayList<String>(Arrays.asList(new String[]{"old","conf","1","2","12","123","txt","bac","bak","backup","asd","dsa","a","aa","aaa","tar.gz","tar","7z","zip","inc"}));
			this.prefixesForFiles = new ArrayList<String>(Arrays.asList(new String[]{"Copy%20of%20", "old_", "Old_"}));
			this.suffixesForFiles = new ArrayList<String>(Arrays.asList(new String[]{"","%20-%20Copy", "_old"}));
			this.suffixCounter = 5;
			this.badResponseKey = "";
			this.timeout = 3600000;
			this.caseSensitve = true;
		}
		
		@Override
		protected void parse() {
			// TODO Auto-generated method stub
			
		}
		
		public void load(FileConfiguration config) {
	       
	    }
	    
	    public void load(String fileName) {
	       
	    }

		public String getBadResponseKey() {
			return badResponseKey;
		}

		public void setBadResponseKey(String badResponseKey) {
			this.badResponseKey = badResponseKey;
		}

		public int getTreadsNum() {
			return treadsNum;
		}

		public void setThreadsNum(int threadsNum) {
			this.threadsNum = threadsNum;
		}

		public ArrayList<String> getBlacklistExtensions() {
			return blacklistExtensions;
		}

		public void setBlacklistExtensions(ArrayList<String> blacklistExtensions) {
			this.blacklistExtensions = blacklistExtensions;
		}

		public long getTimeout() {
			return timeout;
		}

		public void setTimeout(long timeout) {
			this.timeout = timeout;
		}
		
	}
	
	 class ObsoleteFilesPanel extends AbstractParamPanel {


			private JPanel panelSession = null;  //  @jve:decl-index=0:visual-constraint="10,320"
			private ZapTextField txtSessionName = null;
			private ZapTextArea txtDescription = null;
			private JLabel lblErrorKey;
			private JLabel lblThreadsNum;
			private JLabel lblBlacllistExts;
			private JLabel lblListExts;
			private JLabel lblListPrefixes;
			private JLabel lblListSuffixes;
			private JLabel lblTimeout;
			private JLabel lblSuffixCount;
			private JTextField txtErrorKey = null;
			private JTextField txtThreadNum = null;
			private JTextField txtBlacllistExts = null;
			private JTextField txtListExts = null;
			private JTextField txtListPrefixes = null;
			private JTextField txtListSuffixes = null;
			private JTextField txtTimeout = null;
			private JTextField txtSuffixCount = null;
			private JCheckBox chkCase;
			public ObsoleteFilesParam param = null; 
			
		    public ObsoleteFilesPanel() {
		        super();
		 		initialize();
		   }

		    
			/**
			 * This method initializes this
			 * 
			 * @return void
			 */
			private void initialize() {
				this.setLayout(new GridLayout(10,1));
		        this.setName("Good Old Files");
				lblErrorKey = new JLabel("Custom value for wrong page response:");
				lblThreadsNum = new JLabel("Number of parallel threads:");
				lblBlacllistExts = new JLabel("Extensions to ignore when scanning:");
				lblListExts = new JLabel("Extensions to scan:");
				lblListPrefixes = new JLabel("Prefixes to add for each file:");
				lblListSuffixes = new JLabel("Suffixes to add for each file:");
				lblSuffixCount = new JLabel("Suffix counter:");
				lblTimeout = new JLabel("Timeout for scanning a directory (in minutes):");
				txtErrorKey = new JTextField(10);
				txtThreadNum = new JTextField("5", 5);
				txtBlacllistExts = new JTextField("gif,jpg,jpeg,bmp,css,js,doc,docx,pdf,xls,xlsx,xlsm,docm,ppt,pptx,pps,bmp,png,css,xml");
				txtListExts = new JTextField("old,conf,1,2,12,123,txt,bac,bak,backup,asd,dsa,a,aa,aaa,tar.gz,tar,7z,zip,inc");
				txtListPrefixes = new JTextField("Copy%20of%20,old_,Old_");
				txtListSuffixes = new JTextField("%20-%20Copy,_old");
				txtTimeout = new JTextField(3600000/60000 + "", 10);
				txtSuffixCount = new JTextField("5", 10);
				chkCase = new JCheckBox("Case sensitive", true);
				param = new ObsoleteFilesParam();
				param.setBadResponseKey("");
				param.setThreadsNum(5);
				//param.blacklistExtensions = new ArrayList<String>();
				
				
				JPanel tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				tempPanel.add(lblErrorKey);
				tempPanel.add(txtErrorKey);
		        this.add(tempPanel);
		        
		        tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				tempPanel.add(lblThreadsNum);
				tempPanel.add(txtThreadNum);
				this.add(tempPanel);
				
				
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblBlacllistExts);
				 tempPanel.add(txtBlacllistExts);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblListExts);
				 tempPanel.add(txtListExts);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblListPrefixes);
				 tempPanel.add(txtListPrefixes);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblListSuffixes);
				 tempPanel.add(txtListSuffixes);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblSuffixCount);
				 tempPanel.add(txtSuffixCount);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(lblTimeout);
				 tempPanel.add(txtTimeout);
				 this.add(tempPanel);
				 
				 tempPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
				 tempPanel.add(chkCase);
				 this.add(tempPanel);
			}
			
			public String getErrorKey()
			{
				if(txtErrorKey.getText().isEmpty())
					return null;
					
				return txtErrorKey.getText();
			}
			
			public int getThreadsNum()
			{
				if(txtThreadNum.getText().isEmpty())
					return 5;
				
				return Integer.parseInt(txtThreadNum.getText());
			}
			
			/**
			 * This method initializes panelSession	
			 * 	
			 * @return javax.swing.JPanel	
			 */    
			private JPanel getPanelSession() {
				if (panelSession == null) {
					
				}
				return panelSession;
			}
			/**
			 * This method initializes txtSessionName	
			 * 	
			 * @return javax.swing.ZapTextField	
			 */    
			private ZapTextField getTxtSessionName() {
				if (txtSessionName == null) {
					txtSessionName = new ZapTextField();
				}
				return txtSessionName;
			}
			
			public void initParam(Object obj) {
			    OptionsParam optParam = (OptionsParam)obj;
			    optParam.addParamSet(param);
			}
			
			public void validateParam(Object obj) {
			    // no validation needed
			}
			
			public void saveParam (Object obj) throws Exception {
				OptionsParam optParam = (OptionsParam)obj;
				
				ObsoleteFilesParam obsParam = (ObsoleteFilesParam) optParam.getParamSet(ObsoleteFilesParam.class);
				obsParam.setBadResponseKey(getErrorKey());
				obsParam.setThreadsNum(getThreadsNum());
				obsParam.blacklistExtensions = new ArrayList<String>(Arrays.asList(txtBlacllistExts.getText().split(",")));
				obsParam.listExtensions = new ArrayList<String>(Arrays.asList(txtListExts.getText().split(",")));
				obsParam.prefixesForFiles = new ArrayList<String>(Arrays.asList(txtListPrefixes.getText().split(",")));
				obsParam.suffixesForFiles = new ArrayList<String>(Arrays.asList(txtListSuffixes.getText().split(",")));
				obsParam.suffixCounter = Integer.parseInt(txtSuffixCount.getText());
				obsParam.timeout = Long.parseLong(txtTimeout.getText()) * 60000;
				obsParam.caseSensitve = chkCase.isSelected();
				
				GoodOldFiles.param = obsParam;
			}


			@Override
			public String getHelpIndex() {
				// ZAP: added help index support
				return "ui.dialogs.sessprop";
			}
			
		}  //  @jve:decl-index=0:visual-constraint="10,10"

	private final static Pattern patternIIS			= Pattern.compile("Parent Directory", PATTERN_PARAM);
	private final static Pattern patternApache		= Pattern.compile("\\bDirectory Listing\\b.*(Tomcat|Apache)", PATTERN_PARAM);
	
	// general match for directory
	private final static Pattern patternGeneralDir1		= Pattern.compile("\\bDirectory\\b", PATTERN_PARAM);
	private final static Pattern patternGeneralDir2		= Pattern.compile("[\\s<]+IMG\\s*=", PATTERN_PARAM);
	private final static Pattern patternGeneralParent	= Pattern.compile("Parent directory", PATTERN_PARAM);
	private boolean isExecuted;
	private String badResponseKey;
	private int treadsNum;
	public static ObsoleteFilesParam param = null;
	private DirBusterManager dirbusterMan;
	private static ArrayList<String> ScannedDirs;
	private static ArrayList<String> AllUrls;
	private ArrayList<String> scanFiles;
	private static Vector<ExtToCheck> extsVector = new Vector<ExtToCheck>();
	private static boolean firstRun = true;
	private static boolean abortRun = false;
	private static final String dictFile = "dictionary.txt";
	private static boolean guiInitialized = false;
	
	public static void setParams(ObsoleteFilesParam param1)
	{
		param = param1;
	}

	public GoodOldFiles()
	{		
		String[] ROOT = {};
		ObsoleteFilesPanel panel = new ObsoleteFilesPanel();
		
		if(param != null)
			param = new ObsoleteFilesParam();
		/*super();
		disablePlugin = false;
		try {
		    BufferedReader in = new BufferedReader(new FileReader("infilename"));
		    String str;
		    while ((str = in.readLine()) != null) {
		        if(str.contains("BadResponse="))
		        {
		        	badResponseKey = str.split("=")[1];
		        	if(badResponseKey.length() < 1)
		        		badResponseKey = null;
		        }
		        else
		        {
		        	badResponseKey = null;
		        }
		    }
		    in.close();
		    View.getSingleton().getOptionsDialog("")
		} catch (Exception e) {
			badResponseKey = null;
		}*/
		//@SuppressWarnings("unused")
		if(!guiInitialized)
		{
			View.getSingleton().getOptionsDialog("").addParamPanel(ROOT, panel, true);
			guiInitialized = true;
		}
		//View.getSingleton().getMainFrame().geto
		@SuppressWarnings("unused")
		int a = 1;
	}

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getId()
     */
    public int getId() {
        return 90001;
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getName()
     */
    public String getName() {
        
        return "Good Old Files";
    }
    


    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getDependency()
     */
    public String[] getDependency() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getSummary()
     */
    public String getDescription() {
        return "Obsolete application specific file found";
    }
    
    public int getCategory() {
        return Category.MISC;
    }

    public String getSolution() {
        return "Remove obsolete files.";
    }
    
    public String getReference() {
        String ref = "";
        return ref;
    }
    
    public void init() {
    	if(firstRun)
    	{
    		abortRun = false;
    		firstRun = false;
	    	ScannedDirs = new ArrayList<String>();
	    	
	    	if(param == null)
	    		param = new ObsoleteFilesParam();
	    	
	    	extsVector = new Vector<ExtToCheck>();
	    	
	    	AllUrls = new ArrayList<String>();
	    	
	    	scanFiles = getFilenames();
	    	
	    	writeToFile(scanFiles);
    	}
    		
    }
    
    private void writeToFile(ArrayList<String> list)
    {
    	try{
	    		  // Create file 
    		File dictionary = new File(System.getProperty("user.home"), dictFile);
    		
    		if(dictionary.exists())
    		{
    			dictionary.delete();
    			dictionary.createNewFile();
    		}
    		
    		FileWriter fstream = new FileWriter(dictionary);
    		BufferedWriter out = new BufferedWriter(fstream);
    		for (String currString : list)
    		{
    			out.write(currString);
    			out.newLine();
    		}
    		  //Close the output stream
    		out.close();
    		} catch (Exception e){//Catch exception if any
    			abortRun = true;
    			System.err.println("Error: " + e.getMessage());
    			JOptionPane.showMessageDialog(null, "Obsolete URL tests will be aborted, error writing dictionary file - " + e.getMessage());
    		}
    }
    
    private ArrayList<String> getFilenames()
    {
    	Session session = Model.getSingleton().getSession();
		SiteNode root = (SiteNode) session.getSiteTree().getRoot();
		Enumeration<SiteNode> en = root.children();
		ArrayList<String> fileToScan = getFilenamesRecursive(en);
		fileToScan = removeDuplicates(fileToScan);
		
		return fileToScan;
    }
    
    private ArrayList<String> getFilenamesRecursive(Enumeration<SiteNode> en)
    {

    	//Model.getSingleton().getSession().getSiteTree().get
    	ArrayList<String> fileToScan = new ArrayList<String>();
    	//TableSessionUrl dff;
    	
    	try {
    		//Vector<Integer> IdsList = hist.getHistoryList(Model.getSingleton().getSession().getSessionId());
			//for (int i : IdsList)
			while (en.hasMoreElements())
			{
				SiteNode node = en.nextElement();
				
				@SuppressWarnings("unchecked")
				Enumeration<SiteNode> InternalEn = node.children();
				
				if(InternalEn.hasMoreElements())
				{
					fileToScan.addAll(getFilenamesRecursive(InternalEn));
				}
				else
				{
					String filename = node.getNodeName().substring(node.getNodeName().indexOf(':') + 1);
					
					int extLocation = filename.lastIndexOf('.');
					
					if(extLocation == -1)
						continue;
					
					if(filename.indexOf('(') != -1)
						filename = filename.substring(0, filename.indexOf('('));
					
					String ext = filename.substring(extLocation + 1);
					
					AllUrls.add("/" + filename);
					
					if(!param.caseSensitve)
						ext = ext.toLowerCase();
					
					if(param.blacklistExtensions.contains(ext))
						continue;
					else
						extsVector.addAll(handleExtension(ext, param.listExtensions));
					
					filename = filename.substring(0, extLocation);
					
					if(!param.caseSensitve)
						filename = filename.toLowerCase();
					
					fileToScan.addAll(handleFilename(filename));
					fileToScan.addAll(enumFilenameDigits(filename));
					
					fileToScan = removeDuplicates(fileToScan);
					extsVector = removeDuplicates(extsVector);
				}
				
			}
			fileToScan = removeDuplicates(fileToScan);
			
    	}
    	catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return fileToScan;
    }
    
    private Vector<ExtToCheck> removeDuplicates(Vector<ExtToCheck> coll)
    {
    	HashSet<ExtToCheck> hs = new HashSet<ExtToCheck>();
    	hs.addAll(coll);
    	coll.clear();
    	coll.addAll(hs);
    	
    	return coll;
    }
    
    private ArrayList<String> removeDuplicates(ArrayList<String> coll)
    {
    	HashSet<String> hs = new HashSet<String>();
    	hs.addAll(coll);
    	coll.clear();
    	coll.addAll(hs);
    	
    	return coll;
    }

	private void checkIfDirectory(HttpMessage msg) throws URIException {

	    URI uri = msg.getRequestHeader().getURI();
	    uri.setQuery(null);
	    String sUri = uri.toString();
		if (!sUri.endsWith("/")) {
			sUri = sUri + "/";
		}
		msg.getRequestHeader().setURI(new URI(sUri, true));
	
	}
	
	private Vector<ExtToCheck> handleExtension(String ext, ArrayList<String> extsToScan)
	{
		Vector<ExtToCheck> exts = new Vector<ExtToCheck>();
		
		exts.add(new ExtToCheck(ext, true));
		exts.add(new ExtToCheck(ext + "~", true));
		
		for (String currExt : extsToScan)
		{
			exts.add(new ExtToCheck(currExt, true));
			exts.add(new ExtToCheck(currExt + "~", true));
			exts.add(new ExtToCheck(ext + "_" + currExt, true));
			exts.add(new ExtToCheck(ext + "." + currExt, true));
			exts.add(new ExtToCheck(ext + "" + currExt, true));
			//exts.add(new ExtToCheck("", true));
		}
		
		
		return exts;
	}
	
	private ArrayList<String> handleFilename(String filename) 
	{
		ArrayList<String> filenames = new ArrayList<String>();
		
		for (String prefix : param.prefixesForFiles)
		{
			filenames.add(prefix + "" + filename);
		}
		
		for (String suffix : param.suffixesForFiles)
		{
			filenames.add(filename + "" + suffix);
		}
		
		if(!Character.isDigit(filename.charAt(filename.length() - 1)))
			for (int i = 1; i <= param.suffixCounter; i++)
			{
				filenames.add(filename + "" + i);
			}
		
		/*filenames.add(filename);
		filenames.add("Copy%20of%20" + filename);
		filenames.add("Copy%20of%20" + filename);
		filenames.add(filename + "%20-%20Copy");*/
		
		return filenames;
	}
	
	private ArrayList<String> enumFilenameDigits(String filename)
	{
		ArrayList<String> enumDigits = new ArrayList<String>();
		char[] filenameArray = filename.toCharArray();
		for(int i = 0; i < filename.length(); i++)
		{
			if(Character.isDigit(filenameArray[i]))
			{
				if(i == (filename.length() - 1) || !Character.isDigit(filenameArray[i+1]))
				{
					char original = filenameArray[i];
					
					for(int charCount = (int)'1'; charCount <= (int)'9'; charCount++)
					{
						if(charCount == (int)original)
							continue;
						
						filenameArray[i] = (char)charCount;
						enumDigits.add(new String(filenameArray));
					}
					
					filenameArray[i] = original;
				}
			}
		}
		
		return enumDigits;
	}

	@SuppressWarnings("deprecation")
	public void scan() {
	    
		//if(isExecuted)
		//	return;
		
		//isExecuted = true;
		if(abortRun)
			return;
		
	    boolean result = false;
	    HttpMessage msg = getNewMsg();
	    URI scanDir = msg.getRequestHeader().getURI();
	    String scanDirStr;
	    
	    try
	    {
	    	scanDirStr = scanDir.getPath();
	    	
	    	if(scanDirStr == null)
	    	{
	    		if(!firstRun)
	    		{
		    		firstRun = true;
		    		init();
	    		}
	    		
	    		scanDirStr = "/";
	    	}
	    	else
	    	{
	    		if (scanDirStr.lastIndexOf('/') == scanDirStr.indexOf('/'))
	    			return;
	    		else
	    			scanDirStr = scanDirStr.substring(0, scanDirStr.lastIndexOf('/') + 1);
	    	}
	    	
	    	if(ScannedDirs.contains(scanDirStr))
	    		return;
	    	else
	    	{
	    		ScannedDirs.add(scanDirStr);
	    	}
	    }
	    catch(Exception e)
	    {
	    	JOptionPane.showMessageDialog(null, "The URL is Invalid! Files Dictionary test will be aborted!" + e.getMessage());
	    	return;
	    }
	    
	    int reliability = Alert.WARNING;
	    String hostname = msg.getRequestHeader().getHostName();
	    int port = msg.getRequestHeader().getHostPort();
	    
	    String Url = "";
	    
	    if(port == -1)
	    {
	    	port = msg.getRequestHeader().getSecure() ? 443 : 80;
	    	Url = (msg.getRequestHeader().getSecure() ? "https" : "http") + "://" + hostname + scanDirStr;
	    }
	    else
	    	Url = (msg.getRequestHeader().getSecure() ? "https" : "http") + "://" + hostname + ":" + port + scanDirStr;
	    
	    
	    dirbusterMan = new DirBusterManager(this);
	    dirbusterMan.setDefaultNoThreads(GoodOldFiles.param.threadsNum);
	    
	    long timeout = param.timeout;
	    
	    ConnectionParam conParam = Model.getSingleton().getOptionsParam().getConnectionParam();
		
	    if (conParam.isUseProxy(hostname)) {
			dirbusterMan.setProxyRealm(Model.getSingleton().getOptionsParam().getConnectionParam().getProxyChainRealm());
			dirbusterMan.setProxyHost(conParam.getProxyChainName());
			dirbusterMan.setProxyPort(conParam.getProxyChainPort());
			dirbusterMan.setProxyUsername(conParam.getProxyChainUserName());
			dirbusterMan.setProxyPassword(conParam.getProxyChainPassword());
			dirbusterMan.setUseProxy(true);
			dirbusterMan.setUseProxyAuth(true);
	    }
	    
	    try {
			dirbusterMan.setTargetURL(new URL(Url));
		} catch (MalformedURLException e1) {
			JOptionPane.showMessageDialog(null, "The URL is Invalid! Files Dictionary test will be aborted!");
			//isExecuted = true;
			return;
		}
	    
	    
	    /* Build array of filenames */
	    //String dictFile = getDictionaryFile(scanFiles);
	    
	    dirbusterMan.setFileLocation(System.getProperty("user.home") + "\\" + dictFile);
	    dirbusterMan.setDefaultList(System.getProperty("user.home") + "\\" + dictFile);
	    dirbusterMan.setAuto(true);
	    dirbusterMan.setHeadLessMode(true);
	  /*  try {
			dirbusterMan.addBaseCase(GenBaseCase.genBaseCase(Url, false, ""));
			dirbusterMan.addBaseCase(GenBaseCase.genBaseCase(Url, true, null));
			//dirbusterMan.addBaseCase(GenBaseCase.genBaseCase(Url, false, null));
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}*/
	    
	    if(!param.badResponseKey.isEmpty())
	    	dirbusterMan.addFailCaseRegex(param.badResponseKey);
	    else
	    	dirbusterMan.addFailCaseRegex(".*404 Not Found*");
	    
	    
	    //Vector<com.sittinglittleduck.DirBuster.ExtToCheck> extsVector = new Vector<com.sittinglittleduck.DirBuster.ExtToCheck>();
	    //extsVector.add(new ExtToCheck("", true));
	    
	    
	    dirbusterMan.setupManager(scanDirStr, System.getProperty("user.home") + "\\" + dictFile, msg.getRequestHeader().getSecure() ? "https" : "http", hostname, port, null, null, GoodOldFiles.param.threadsNum, false, true, true, true, extsVector);
	    
	    dirbusterMan.start();
		
		try {
			java.lang.Thread.sleep(1000);
		} catch (InterruptedException e) {
		}

		int timePassed = 0;
		
		while( ! dirbusterMan.hasFinished()) {
			/*if (stopScan) {
				isPaused = false;
				manager.youAreFinished();
			}
			if (pauseScan) {
				manager.pause();
				pauseScan = false;
				isPaused = true;
			}
			if (unpauseScan) {
				manager.unPause();
				unpauseScan = false;
				isPaused = false;
			}*/
			//System.out.println("Done so far " +  manager.getTotalDone());
			//System.out.println("Dirs found  " +  manager.getTotalDirsFound());
			//System.out.println("Worker count " +  manager.getWorkerCount());
			//System.out.println("Done " +  manager.getTotalDone() + "/" + manager.getTotal());
			
			if(dirbusterMan.getTotal() == dirbusterMan.getTotalDone())
			{
				dirbusterMan.youAreFinished();
				break;
			}
			
			this.scanProgress(scanDirStr, port, dirbusterMan.getTotalDone(), dirbusterMan.getTotal());
			
			
			try {
				java.lang.Thread.sleep(1000);
				timePassed += 1000;
				if(timePassed >= timeout)
				{
					dirbusterMan.youAreFinished();
					return;
				}
				
			} catch (InterruptedException e) {
			}
		}
	    
	   /* try {
            checkIfDirectory(msg);
            writeProgress(msg.getRequestHeader().getURI().toString());
    		sendAndReceive(msg);

    		if (msg.getResponseHeader().getStatusCode() != HttpStatusCode.OK) {
    			return;
    		}

        } catch (IOException e) {
        	 
        }
		
		if (result) {
            bingo(Alert.RISK_MEDIUM, reliability, msg.getRequestHeader().getURI().toString(), "", "", msg);
		}*/
	}

	@Override
	public void scanFinshed(String host) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void scanProgress(String host, int port, int done, int todo) {
		// TODO Auto-generated method stub
		
	}

	@SuppressWarnings("deprecation")
	@Override
	public void foundDir(URL url, int statusCode, String responce,
			String baseCase, String rawResponce, BaseCase baseCaseObj) {
		// TODO Auto-generated method stub
		
		String encodedUrl = url.toString().replaceAll("%", "%25");
		for (String uri : AllUrls)
		{
			if(encodedUrl.toString().endsWith(uri))
				return;
		}
		
		try {
			bingo(Alert.RISK_MEDIUM, Alert.WARNING, url.toString(), "", "", "", new HttpMessage(new URI(url.toString())));
		} catch (URIException | HttpMalformedHeaderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public int getRisk() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getCweId() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getWascId() {
		// TODO Auto-generated method stub
		return 0;
	}
	
	/*public String getDictionaryFile(ArrayList filenames)
	{
		return "c:\\temp\\dictionary.txt";
	}*/
    
}

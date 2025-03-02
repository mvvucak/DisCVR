package gui;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

/***
 * Formats the input panel for DisCVR's GUI
 * 
 * @author Maha Maabar
 *
 */

public class InputPanel extends JPanel implements ActionListener {
	private static final long serialVersionUID = 1L;

	private TextListener fileListener;	
	private JLabel sampleFileLabel;
	private JTextField sampleFileField;
	private JButton sampleFileButton;
	
	private JRadioButton dbButton1;
	private JRadioButton dbButton2;
	private JRadioButton dbButton3;
	private ButtonGroup dbLibraryGroup;
	
	private JCheckBox customisedDB;
	private JLabel dbNameLabel;
	private JLabel entropyLabel;
	
	private JTextField dbNameField;
	private JTextField entropyField;
	
	private JButton dbNameButton;
	
	private JButton classifyButton;
	
	private OptionListener optionListener;
	
	public InputPanel ()  {
		
		Dimension dim = getPreferredSize();
		dim.width = 500;
		dim.height = 200;
		setPreferredSize(dim);
		setMinimumSize(dim);
		
		setLayout (new BorderLayout ());		
		
		Border innerBorder = BorderFactory.createTitledBorder(null,"Input Sources",TitledBorder.LEFT, TitledBorder.TOP, new Font("Verdana",Font.BOLD,12), Color.BLACK);
		Border outerBorder = BorderFactory.createEmptyBorder(5,5,5,5);
		setBorder(BorderFactory.createCompoundBorder(outerBorder, innerBorder));
		
		sampleFileLabel = new JLabel("Sample File: ");
		sampleFileField = new JTextField (15);
		
		sampleFileButton = new JButton ("Browse");		
			
		//set up the database libraries
		dbButton1 = new JRadioButton("Haemorrhagic Viruses");
		dbButton2 = new JRadioButton("Respiratory Viruses");
		dbButton3 = new JRadioButton("Human Pathogenic Viruses");
				
		dbButton1.setActionCommand("HaemorrhagicVirusDB");
		dbButton2.setActionCommand("RespiratoryVirusDB");
		dbButton3.setActionCommand("HSEVirusDB");
		dbLibraryGroup = new ButtonGroup();
				
		dbLibraryGroup.add(dbButton1);
		dbLibraryGroup.add(dbButton2);
		dbLibraryGroup.add(dbButton3);	
		
		//set up the fields for customised DB 
		customisedDB = new JCheckBox();
		dbNameLabel = new JLabel("Database Name:");
		dbNameButton = new JButton ("Browse");
		entropyLabel = new JLabel("Entropy Threshold:");
		
		dbNameField = new JTextField(15);
		entropyField = new JTextField(5);
		
		//default setting: all its fields are disabled
		dbNameLabel.setEnabled(false);
		dbNameButton.setEnabled(false);
		entropyLabel.setEnabled(false);
		
		dbNameField.setEnabled(false);
		entropyField.setEnabled(false);
		
		//When the customised DB checkBox is checked, its fields are editable 
		//and the Database Library buttons become unavailable
		customisedDB.addActionListener(new ActionListener(){
                 public void actionPerformed(ActionEvent e) {
                	 boolean isTicked = customisedDB.isSelected();
                	 dbNameLabel.setEnabled(isTicked);
                	 dbNameButton.setEnabled(isTicked);
             		 entropyLabel.setEnabled(isTicked);
             		 dbNameField.setEnabled(isTicked);
             		 entropyField.setEnabled(isTicked);
             		 
             		 //empty the fields when customised DB is unchecked
             		 dbNameField.setText(""); 
             		 entropyField.setText("");
             		 
             		 dbButton1.setEnabled(!isTicked);
             		 dbButton2.setEnabled(!isTicked);
             		 dbButton3.setEnabled(!isTicked);
			}			
		});
				
		//set up the classify button
		classifyButton = new JButton ("Classify");
		
		initComponents();				
		
		//add ActionListener to the buttons
		//When the Sample File Browse button is clicked
		sampleFileButton.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JFileChooser inputFileChooser = new JFileChooser();
				InputFileFilter filter = new InputFileFilter();
				
				inputFileChooser.setFileFilter(filter);
				int retVal = inputFileChooser.showOpenDialog((Component)e.getSource());
				if (retVal ==JFileChooser.APPROVE_OPTION){
					String sampleFilePath = inputFileChooser.getSelectedFile().getAbsolutePath();
					sampleFileField.setText(sampleFilePath);
				}
			}			
		});
		
		//When the customisedDB Browse button is clicked
		dbNameButton.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				JFileChooser inputFileChooser = new JFileChooser();				
				int retVal = inputFileChooser.showOpenDialog((Component)e.getSource());
				if (retVal ==JFileChooser.APPROVE_OPTION){
					String dbFilePath = inputFileChooser.getSelectedFile().getAbsolutePath();
					dbNameField.setText(dbFilePath);
				}
			}		
		});
				
		//When classify button is clicked
		classifyButton.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				String inputFile = sampleFileField.getText();
				String format ="";
				
				if(!inputFile.equalsIgnoreCase("")){
					if(inputFile.endsWith(".fa")||inputFile.endsWith(".fasta"))
						format = "fasta";
					if (inputFile.endsWith(".fq")||inputFile.endsWith(".fastq"))
						format = "fastq";
					if (inputFile.endsWith(".fa.gz")||inputFile.endsWith(".fasta.gz"))
						format = "fastagz";
					if (inputFile.endsWith(".fq.gz")||inputFile.endsWith(".fastq.gz"))
						format = "fastqgz";	
					
					//create an optionEvent object
					String dbOption = null ;
					String dbLibrary; 
					String kSize = "";
					String entropyThrshld = "" ;
					
					if(customisedDB.isSelected()){
					  dbOption ="customisedDB";
					  dbLibrary=dbNameField.getText();
					  					  
					  //get the kSize from the name of the dbLibrary
					  kSize = dbLibrary.substring(dbLibrary.lastIndexOf('_')+1,dbLibrary.length());
					  //if no value is specified for entropy, then default value is used
					  entropyThrshld = entropyField.getText();
					  if(entropyThrshld.isEmpty()){
						  entropyThrshld = "2.5";
						  entropyField.setText(entropyThrshld);
					  }					 
					}
					else{
						dbOption ="BuiltInDB";
						dbLibrary = dbLibraryGroup.getSelection().getActionCommand();
					}					
					if(dbLibrary.isEmpty()){
						JOptionPane.showMessageDialog(null, "You have not selected a customised database file!", "Information",
					            JOptionPane.INFORMATION_MESSAGE);						
					}
					else{
						OptionEvent oe = new OptionEvent(this, inputFile, format, dbOption, dbLibrary, kSize, entropyThrshld);
						if(optionListener != null) 	{
							optionListener.optionEventOccurred(oe);					
						}
					}						
				}				
				else{
					JOptionPane.showMessageDialog(null, "You have not selected a file!", "Information",
				            JOptionPane.INFORMATION_MESSAGE);
				}
			}			
		});		
	}

	//listens to sample file selection
	public void actionPerformed(ActionEvent e) {
		String fileName = sampleFileField.getText(); //sample file name
		
		if(fileListener != null)
			fileListener.textProduced(fileName+"\n");
		else{
			fileListener.textProduced("");
		}
		
	}

	public void disableClassifyButton(){
		classifyButton.setEnabled(false);
	}

	public void enableClassifyButton(){
		classifyButton.setEnabled(true);
	}
	
	public void setFileListener(TextListener listener) {
		this.fileListener = listener;
	}

	public void resetAll(){
		sampleFileField.setText("");
		dbLibraryGroup.clearSelection();
		customisedDB.setSelected(false);
		//default setting: all its fields are disabled
		dbNameLabel.setEnabled(false);
		dbNameButton.setEnabled(false);
		entropyLabel.setEnabled(false);

		dbNameField.setEnabled(false);
		entropyField.setEnabled(false);

		classifyButton.setEnabled(true);
	}
	
	//formats the panel with the different components
	private void initComponents() {
        
       setLayout (new GridBagLayout());
		
	   GridBagConstraints gc = new GridBagConstraints();
	   
	   gc.fill = GridBagConstraints.NONE; // Do not resize the component
	   //sets the cell weight relative to other components
	   gc.weightx = 1; //horizontal space
	   
	   /////////////////  (Sample File Row) ////////////////////////////
	   gc.weighty = 1;//sets the space between this and next component vertically
	   
	   gc.gridy=0; //First row
	   
	   gc.gridx = 0; //the first component 	   
       gc.anchor = GridBagConstraints.LINE_END; //put the components where the lines of the text starts
	   gc.insets = new Insets(0,0,0,5); //to pad spaces between component and edges
	   add(sampleFileLabel, gc);
		
	   //the second component 
	   gc.gridx = 1; //second column		
	   gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text start
	   gc.insets = new Insets(0,0,-5,0); //to pad spaces between component and edges
	   add(sampleFileField, gc);
		
		//the third component 
		gc.gridx = 2; //second column				
		gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text start
		gc.insets = new Insets(0,0,0,0); //to pad spaces between component and edges
		add(sampleFileButton, gc);
	        
        ///////////////// (Haemorrhagic DB button)////////////////////////////
		gc.gridy++; //go to next row
		
		gc.weighty = 0.1; //sets the space between this and next component vertically
		
        gc.gridx = 0; //first column
        gc.insets = new Insets(0,0,0,5);
        gc.anchor = GridBagConstraints.LINE_END;
        add(new JLabel("Database Library: "), gc);

        gc.gridx = 1; //second column so the button is in the middle		 
        gc.anchor = GridBagConstraints.FIRST_LINE_START;
        gc.insets = new Insets(0,0,0,0);
        add(dbButton1, gc);

        ///////////////// (Respiratory DB button)////////////////////////////
        gc.gridy++; //go to next row
        
        gc.weighty = 0.1; //sets the space between this and next component vertically        
        
        gc.gridx = 1; //second column so the button is in the middle		 
        gc.anchor = GridBagConstraints.FIRST_LINE_START;
        gc.insets = new Insets(0,0,0,0);
        add(dbButton2, gc);

        /////////// (HSE DB button)/////////////////////////        
        gc.gridy++; //go to next row

        gc.weighty = 1; //sets the space between this and next component vertically

        gc.gridx = 1; //second column so the button is in the middle		 
        gc.anchor = GridBagConstraints.FIRST_LINE_START;
        gc.insets = new Insets(0,0,0,0);
        add(dbButton3, gc);

        /////////// (customised DB checkBox)/////////////////////////
        gc.gridy++; //go to next row

        gc.weighty = 0.2;//sets the space between this and next component vertically

        gc.gridx = 0; 
        gc.insets = new Insets(0,0,0,0);		 
        gc.anchor = GridBagConstraints.FIRST_LINE_START;
        add(new JLabel("Customised Database:"), gc);
        
        gc.gridx = 1;
        gc.anchor = GridBagConstraints.FIRST_LINE_START;
        gc.insets = new Insets(0,0,0,0);
        add(customisedDB, gc);
        
        ///////////////// Next row (customised DB Name) ////////////////////////////
        gc.gridy++; //go to next row

        gc.weighty = 0.2;//sets the space between this and next component vertically
        
        gc.gridx = 0; //the first component 	   
        gc.anchor = GridBagConstraints.LINE_END; //put the components where the lines of the text starts
 	    gc.insets = new Insets(0,0,0,5); //to pad spaces between component and edges
 	    add(dbNameLabel, gc);
 		
 	    //the second component 
 	    gc.gridx = 1; //second column		
 	    gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text start
 	    gc.insets = new Insets(0,0,-5,0); //to pad spaces between component and edges
 	    add(dbNameField, gc);
 		
 		//the third component 
 		gc.gridx = 2; //second column				
 		gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text start
 		gc.insets = new Insets(0,0,0,0); //to pad spaces between component and edges
 		add(dbNameButton, gc);
        
 		///////////////// Next row (customised DB Entropy Threshold) ////////////////////////////
        gc.gridy++; //go to next row

        gc.weighty = 0.2;//sets the space between this and next component vertically

        gc.gridx = 0; //first column
        gc.fill = GridBagConstraints.NONE; // Do not resize the component
        gc.anchor = GridBagConstraints.LINE_END; //put the components where the lines of the text starts
        gc.insets = new Insets(0,0,0,5); //to pad spaces between component and edges
        add(entropyLabel, gc);

        //the second component 
        gc.gridx = 1; //second column
        gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text start
        gc.insets = new Insets(0,0,-5,0); //to pad spaces between component and edges
        add(entropyField, gc);
        
        /////////// Last row (Classify Button) /////////////////////////        
        gc.gridy++; //increment the vertical position

        gc.weighty = 2;//sets the space between this and next component vertically
        
        gc.gridx = 1; //second column so it is in the middle
        gc.anchor = GridBagConstraints.LINE_START; //put the components where the lines of the text end
        gc.insets = new Insets(0,0,0,0); //to pad spaces between component and edges
        add(classifyButton, gc);

   }
	
	public void setOptionListener (OptionListener listener) {
		this.optionListener = listener;
	}


}

	



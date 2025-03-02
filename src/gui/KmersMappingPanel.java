package gui;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Image;
import java.net.URL;
import java.text.NumberFormat;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.AxisLocation;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.labels.StandardXYItemLabelGenerator;
import org.jfree.chart.labels.XYItemLabelGenerator;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.StackedXYBarRenderer;
import org.jfree.chart.renderer.xy.StandardXYBarPainter;
import org.jfree.chart.renderer.xy.XYBarRenderer;
import org.jfree.data.xy.DefaultTableXYDataset;
import org.jfree.data.xy.TableXYDataset;
import org.jfree.data.xy.XYSeries;

/***
 * A class to show a graph of mapping matched k-mers to a reference genome.
 * It uses JFreechart package to create a bar graph.
 * 
 * @author Maha Maabar
 *
 */
public class KmersMappingPanel extends JFrame {

    private static final long serialVersionUID = 1L;
    
    public KmersMappingPanel (int [][] positions,String name, String text){
		 super("Reference Genome Alignment");
		 
		 StyledDocument document = setStyle(text);
	     
		 JTextPane textPane = new JTextPane(document);
	     textPane.setEditable(false);
	     	        
	     JTextArea textArea = new JTextArea(text,6,6);
	     textArea.setPreferredSize(new Dimension(50,50));
	     textArea.setLineWrap(true);
	        
	     Font font = new Font("verdana", Font.BOLD, 16);
	     textArea.setFont(font);
	     textArea.setForeground(Color.BLACK);
	        
	     add(textArea, BorderLayout.NORTH);
		 
		 TableXYDataset tablexydataset = createDataset(positions);
	    
		 JPanel chartPanel  = createChart(tablexydataset, name);         
         
         
         add(chartPanel, BorderLayout.CENTER);
	     
	     setIconImage(createIcon("cvr_logo.gif"));
	 
	     setSize(640, 480);
	     setLocationRelativeTo(null);
	 }

    //creates the dataset for the bar graph
	private TableXYDataset createDataset(final int [][] data) {
    	DefaultTableXYDataset defaulttablexydataset = new DefaultTableXYDataset();   
        
        int numOfRows = (data.length);// number of mismatches
		int numOfCols = (data[0].length);//reference genome length
        
		for(int row = 0; row < numOfRows; row++){
			String key = rowKey(row);
			XYSeries xyseries = new XYSeries(key, true, false);
			
			for(int col=0; col < numOfCols; col++){				
				xyseries.add(col+1, data[row][col]);  
			}
			defaulttablexydataset.addSeries(xyseries); 
		}
		return defaulttablexydataset; 
    }    
  
    //sets label for each row in the data
    private String rowKey (final int row){
    	String description = null;
    	switch (row){
    	case 0:
    		description = "0-mismatch";
    		break;
    	case 1:
    		description = "1-mismatch";
    		break;
    	case 2: 
    		description = "2-mismatch";
    		break;
    	case 3:
    		description = "3-mismatch";
    		break;
    	}    	
    	return description;
    }
    
    
    private JPanel createChart(final TableXYDataset  dataset, String VirusName) {
    	final JFreeChart chart = ChartFactory.createStackedXYAreaChart(
    			"Matched K-mers Mapping to "+VirusName,  // chart title
                "Reference Genome Positions",            // domain axis label
                "Counts of Mapped K-mers",               // range axis label
                dataset,                     // data
                PlotOrientation.VERTICAL,    // the plot orientation
                true,                        // legend
                true,                        // tooltips
                false                        // urls
         );
    	 
    	 XYBarRenderer renderer = new StackedXYBarRenderer(0.0);
         renderer.setBarPainter(new StandardXYBarPainter());
         renderer.setDrawBarOutline(true);// so the different colors will be visible
         renderer.setShadowVisible(true);
    	// get a reference to the plot for further customisation...
    	final  XYPlot plot = new XYPlot(dataset,
                 new NumberAxis("Reference Genome Positions"),
                 new NumberAxis("Counts of Mapped K-mers"), 
                 renderer);
        
         plot.setRangeAxisLocation(AxisLocation.BOTTOM_OR_LEFT);
         
         plot.getDomainAxis().setLowerMargin(0.0);
         plot.getDomainAxis().setUpperMargin(0.0);
         
         chart.setBackgroundPaint(Color.white);
         
         // change the auto tick unit selection to integer units only...
         final NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
        
         rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
         
         
         plot.setBackgroundPaint(Color.lightGray);
  	   
 	     plot.setDomainGridlinePaint(Color.white);
 	     plot.setRangeGridlinePaint(Color.white);
 	        
 	     rangeAxis.setAutoRangeIncludesZero(true);
 	     
 	     //set the font for the axes titles
 	     Font font = new Font("Dialog", Font.BOLD,25); 
 	     plot.getDomainAxis().setLabelFont(font);
 	     plot.getRangeAxis().setLabelFont(font);
 	     
 	    ValueAxis axis = plot.getDomainAxis();

 	     ValueAxis axis2 = plot.getRangeAxis();

 	     axis.setTickLabelFont(new Font("verdana",Font.BOLD, 15));
 	     axis2.setTickLabelFont(new Font("verdana",Font.BOLD,15));
 	     
 	    // label the points
        NumberFormat format = NumberFormat.getNumberInstance();
        format.setMaximumFractionDigits(2);
        XYItemLabelGenerator generator =
            new StandardXYItemLabelGenerator(
                StandardXYItemLabelGenerator.DEFAULT_ITEM_LABEL_FORMAT,
                format, format);
        renderer.setBaseItemLabelGenerator(generator);
        renderer.setBaseItemLabelsVisible(true);
       
        return new ChartPanel(chart);
        
    }

    //sets the icon for the frame 
	private Image createIcon (String path) {
			URL url = ClassLoader.getSystemResource(path);
			
			if(url == null) {
				System.err.println("Unable to load image: "+ path);
			}
			
			Image icon = new ImageIcon (url).getImage();
			
			return icon;
		}
	 
	//style the document in the text area part of the graph	
	private static StyledDocument setStyle(String text){
		StyleContext context = new StyleContext();
	    StyledDocument document = new DefaultStyledDocument(context);

	    Style style = context.getStyle(StyleContext.DEFAULT_STYLE);
	    StyleConstants.setAlignment(style, StyleConstants.ALIGN_CENTER);
	    StyleConstants.setFontSize(style, 16);
	    StyleConstants.setSpaceAbove(style, 4);
	    StyleConstants.setSpaceBelow(style, 2);
	        
	    try {
	      document.insertString(document.getLength(), text, style);
	    } catch (BadLocationException badLocationException) {
	        System.err.println("Bad Location!");
	    }
	      return document;
	}

}
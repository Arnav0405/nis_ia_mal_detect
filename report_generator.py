from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from datetime import datetime
from textwrap import wrap

def wrap_text(text, width=30):
    """Wrap text to specified width"""
    return '\n'.join(wrap(str(text), width))

def generate_report(data, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )
    
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#1976d2')
    ))
    
    elements = []
    
    # Header
    elements.append(Paragraph("Security Analysis Report", styles['CustomTitle']))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Process each file
    for filename, file_results in data.get('files', {}).items():
        elements.append(Paragraph(f"File: {filename}", styles['Heading2']))
        
        # Malware Classification Summary
        if 'malwareClassification' in file_results:
            classification = file_results['malwareClassification']
            
            # Create a summary table with wrapped text
            summary_data = [
                ['Malware Classification Summary', ''],
                ['Predicted Type', wrap_text(classification['predicted_malware'], 40)],
                ['Confidence', f"{(classification['max_probability'] * 100):.2f}%"]
            ]
            
            summary_table = Table(summary_data, colWidths=[6*cm, 10*cm])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('SPAN', (0, 0), (1, 0)),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 12))
            
            # Detailed probability table with wrapped text
            prob_data = [['Classification Type', 'Probability']]
            sorted_probs = sorted(
                classification['probabilities'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            prob_data.extend([
                [wrap_text(k, 40), f"{(v * 100):.2f}%"] 
                for k, v in sorted_probs
            ])
            
            prob_table = Table(prob_data, colWidths=[12*cm, 4*cm])
            prob_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f5f5f5')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
            ]))
            elements.append(prob_table)
            elements.append(Spacer(1, 20))

        # File Analysis Results
        for scan_type, scan_results in file_results.items():
            if scan_type != 'malwareClassification':
                elements.append(Paragraph(f"{scan_type.upper()} Analysis", styles['Heading3']))
                
                # Basic file info table
                info_data = [['Property', 'Value']]
                info_data.extend([
                    ['File Size', f"{scan_results.get('file_size', 'N/A')} bytes"],
                    ['File Type', scan_results.get('file_type', 'N/A')]
                ])
                
                if 'hashes' in scan_results:
                    for hash_type, hash_value in scan_results['hashes'].items():
                        info_data.append([
                            hash_type.upper(),
                            hash_value
                        ])
                
                table = Table(info_data, colWidths=[4*cm, 12*cm])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 12))
        
        elements.append(PageBreak())
    
    doc.build(elements)

def generate_log_report(data, output_path):
    """Generate PDF report for log analysis results"""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )
    
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    elements.append(Paragraph("Log Analysis Report", styles['Heading1']))
    elements.append(Spacer(1, 20))
    
    # File Info
    if data.get('file'):
        elements.append(Paragraph(f"File: {data['file']}", styles['Heading2']))
        elements.append(Paragraph(f"Total Lines: {data.get('total_lines', 'N/A')}", styles['Normal']))
        elements.append(Paragraph(f"Flagged Percentage: {data.get('flagged_percentage', 0)}%", styles['Normal']))
        elements.append(Spacer(1, 20))
    
    # Flag Summary
    if data.get('flag_summary'):
        elements.append(Paragraph("Detection Summary", styles['Heading2']))
        summary_data = [['Pattern', 'Count']]
        summary_data.extend([
            [rule.replace('_', ' ').upper(), str(count)]
            for rule, count in data['flag_summary'].items()
        ])
        
        summary_table = Table(summary_data, colWidths=[12*cm, 4*cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
    
    # Recommendations
    if data.get('recommendations'):
        elements.append(Paragraph("Recommendations", styles['Heading2']))
        for rec in data['recommendations']:
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
        elements.append(Spacer(1, 20))
    
    # Detailed Flags
    if data.get('flags'):
        elements.append(Paragraph("Detected Issues", styles['Heading2']))
        flag_data = [['Rule', 'Description', 'Line']]
        flag_data.extend([
            [flag['rule'].replace('_', ' '), 
             wrap_text(flag['description'], 40),
             str(flag['line'])]
            for flag in data['flags']
        ])
        
        flag_table = Table(flag_data, colWidths=[5*cm, 9*cm, 2*cm])
        flag_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(flag_table)
    
    doc.build(elements)

def format_dict_content(data: dict, indent=0) -> str:
    """Format dictionary content with proper indentation and line breaks"""
    result = []
    for key, value in data.items():
        key_str = key.replace('_', ' ').title()
        if isinstance(value, dict):
            result.append(f"{'  ' * indent}{key_str}:")
            result.append(format_dict_content(value, indent + 1))
        elif isinstance(value, list):
            result.append(f"{'  ' * indent}{key_str}:")
            result.append(format_list_content(value, indent + 1))
        else:
            result.append(f"{'  ' * indent}{key_str}: {value}")
    return '\n'.join(result)

def format_list_content(data: list, indent=0) -> str:
    """Format list content with proper indentation and line breaks"""
    return '\n'.join(f"{'  ' * indent}- {item}" for item in data)


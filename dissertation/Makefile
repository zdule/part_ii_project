# This is the Makefile for the demonstration dissertation
# written by Martin Richards
#
# Note that continuation lines require '\'
# and that TAB is used after ':' and before unix commands.

DISS = diss.tex refs.bib 
out = build
latex_flags = -output-directory=$(out) -interaction=nonstopmode

$(out)/diss.pdf: $(DISS)	
	mkdir -p $(out)
	xelatex $(latex_flags) diss.tex
	biber --input-directory=$(out) --output-directory=$(out) diss
	xelatex $(latex_flags) diss.tex

$(out)/report.pdf: report.tex
	xelatex $(latex_flags) report.tex
	detex report.tex | tr -cd '0-9A-Za-z \n' | wc -w

count:
	detex diss.tex | tr -cd '0-9A-Za-z \n' | wc -w

monitor:
	printf '%s\n' $(DISS) | entr make $(out)/diss.pdf

monitor_rep:
	echo report.tex | entr make $(out)/report.pdf

clean:
	rm $(out)/*
	rm -f diss.ps *.dvi *.aux *.log *.err
	rm -f core *~ *.lof *.toc *.blg *.bbl

vendors:
	test ! -d $@
	mkdir vendors
	@./source.sh

pagejaune.hvt.target: | vendors
	@echo " BUILD pagejaune.exe"
	@dune build --root . --profile=release ./unikernels/pagejaune.exe
	@echo " DESCR pagejaune.exe"
	@$(shell dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernels/pagejaune.exe 1> $@ 2>&1)

pagejaune.hvt: pagejaune.hvt.target
	@echo " COPY pagejaune.hvt"
	@cp $(file < pagejaune.hvt.target) $@
	@chmod +w $@
	@echo " STRIP pagejaune.hvt"
	@strip $@

pageblanche.hvt.target: | vendors
	@echo " BUILD pageblanche.exe"
	@dune build --root . --profile=release ./unikernels/pageblanche.exe
	@echo " DESCR pageblanche.exe"
	@$(shell dune describe location \
		--context solo5 --no-print-directory --root . --display=quiet \
		./unikernels/pageblanche.exe 1> $@ 2>&1)

pageblanche.hvt: pageblanche.hvt.target
	@echo " COPY pageblanche.hvt"
	@cp $(file < pageblanche.hvt.target) $@
	@chmod +w $@
	@echo " STRIP pageblanche.hvt"
	@strip $@

annuaire.ban.exe.target: | vendors
	@echo " BUILD bin/ban.exe"
	@dune build --root . --profile=release ./bin/ban.exe
	@echo " DESCR bin/ban.exe"
	@$(shell dune describe location \
		 --context default --no-print-directory --root . --display=quiet \
		 ./bin/ban.exe 1> $@ 2>&1)

annuaire.ban.exe: annuaire.ban.exe.target
	@echo " COPY ban.exe"
	@cp $(file < annuaire.exe.target) $@

annuaire.install: pagejaune.hvt pageblanche.hvt
	@echo " GEN annuaire.install"
	@ocaml install.ml > $@

all: annuaire.install | vendors

.PHONY: clean
clean:
	if [ -d vendors ] ; then rm -fr vendors ; fi
	rm -f pagejaune.hvt.target
	rm -f pagejaune.hvt
	rm -f pageblanche.hvt.target
	rm -f pageblanche.hvt
	rm -f annuaire.install

install: annuaire.install
	@echo " INSTALL annuaire"
	opam-installer annuaire.install

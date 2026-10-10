PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
UNITDIR := /etc/systemd/system

SVC := ipsum2nft.service
TMRS := ipsum2nft.timer ipsum2nft-boot.timer

.PHONY: install uninstall

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 ipsum2nft.py $(DESTDIR)$(BINDIR)/ipsum2nft
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 $(SVC) $(DESTDIR)$(UNITDIR)/$(SVC)
	install -m 0644 $(TMRS) $(DESTDIR)$(UNITDIR)/
	@echo "Installed:"
	@echo "  $(DESTDIR)$(BINDIR)/ipsum2nft"
	@echo "  $(DESTDIR)$(UNITDIR)/$(SVC)"
	@echo "  $(addprefix $(DESTDIR)$(UNITDIR)/,$(TMRS))"
	@echo "Next steps (as root):"
	@echo "  systemctl daemon-reload"
	@echo "  systemctl enable --now $(TMRS)"

uninstall:
	-systemctl disable --now $(TMRS)
	rm -f $(BINDIR)/ipsum2nft $(UNITDIR)/$(SVC) $(addprefix $(UNITDIR)/,$(TMRS))
	-systemctl daemon-reload

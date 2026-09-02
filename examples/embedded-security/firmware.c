/* Firmware-style CGULL-047 semantic-profile fixtures.
 *
 * These declarations describe the canonical API names modeled by the
 * embedded-security profile.  Implementations are intentionally omitted.
 */

void mailbox_receive(unsigned *value);
void uart_receive(unsigned *value);
void spi_receive(unsigned *value);
void i2c_receive(unsigned *value);
void dma_descriptor_receive(unsigned *descriptor);
void firmware_image_receive(unsigned *image);
void update_manifest_receive(unsigned *manifest);

int validate_bounds(unsigned value);
int validate_range(unsigned value);
int authenticate_request(unsigned value);
int authorize_request(unsigned value);
int verify_signature(unsigned value);
int check_version(unsigned value);
int check_rollback(unsigned value);
int check_allowlist(unsigned value);

void flash_write(unsigned address);
void flash_erase(unsigned address);
void nvram_write(unsigned value);
void mmio_write(unsigned offset, unsigned value);
void dma_start(unsigned descriptor);
void debug_enable(unsigned command);
void boot_image_accept(unsigned image);
void update_activate(unsigned manifest);

/* mailbox -> flash */
void mailbox_flash_unsafe(void) {
    unsigned address;
    mailbox_receive(&address);
    flash_write(address);
}

void mailbox_flash_safe(void) {
    unsigned address;
    mailbox_receive(&address);
    if (!validate_bounds(address)) return;
    if (!authorize_request(address)) return;
    flash_write(address);
}

/* UART -> MMIO */
void uart_mmio_unsafe(void) {
    unsigned offset;
    unsigned value;
    uart_receive(&offset);
    uart_receive(&value);
    mmio_write(offset, value);
}

void uart_mmio_safe(void) {
    unsigned offset;
    unsigned value;
    uart_receive(&offset);
    uart_receive(&value);
    if (!validate_range(offset)) return;
    if (!check_allowlist(offset)) return;
    if (!authorize_request(value)) return;
    mmio_write(offset, value);
}

/* SPI -> NVRAM */
void spi_nvram_unsafe(void) {
    unsigned value;
    spi_receive(&value);
    nvram_write(value);
}

void spi_nvram_safe(void) {
    unsigned value;
    spi_receive(&value);
    if (!validate_bounds(value)) return;
    if (!authorize_request(value)) return;
    nvram_write(value);
}

/* I2C -> flash erase */
void i2c_flash_erase_unsafe(void) {
    unsigned sector;
    i2c_receive(&sector);
    flash_erase(sector);
}

void i2c_flash_erase_safe(void) {
    unsigned sector;
    i2c_receive(&sector);
    if (!validate_range(sector)) return;
    if (!authorize_request(sector)) return;
    flash_erase(sector);
}

/* less-trusted DMA descriptor -> DMA engine */
void dma_unsafe(void) {
    unsigned descriptor;
    dma_descriptor_receive(&descriptor);
    dma_start(descriptor);
}

void dma_safe(void) {
    unsigned descriptor;
    dma_descriptor_receive(&descriptor);
    if (!validate_bounds(descriptor)) return;
    if (!authorize_request(descriptor)) return;
    dma_start(descriptor);
}

/* update image -> signature/version checks -> boot acceptance */
void image_accept_unsafe(void) {
    unsigned image;
    firmware_image_receive(&image);
    if (verify_signature(image) != 0) return;
    boot_image_accept(image); /* missing version check */
}

void image_accept_safe(void) {
    unsigned image;
    firmware_image_receive(&image);
    if (verify_signature(image) != 0) return;
    if (check_version(image) != 0) return;
    boot_image_accept(image);
}

/* manifest -> signature/version/authz -> update activation */
void update_activate_unsafe(void) {
    unsigned manifest;
    update_manifest_receive(&manifest);
    if (verify_signature(manifest) != 0) return;
    if (check_version(manifest) != 0) return;
    update_activate(manifest); /* missing authorization */
}

void update_activate_safe(void) {
    unsigned manifest;
    update_manifest_receive(&manifest);
    if (verify_signature(manifest) != 0) return;
    if (check_rollback(manifest) != 0) return;
    if (!authorize_request(manifest)) return;
    update_activate(manifest);
}

/* authenticated/authorized debug enablement */
void debug_enable_unsafe(void) {
    unsigned command;
    mailbox_receive(&command);
    if (!authorize_request(command)) return;
    debug_enable(command); /* missing authentication */
}

void debug_enable_safe(void) {
    unsigned command;
    mailbox_receive(&command);
    if (!authenticate_request(command)) return;
    if (!authorize_request(command)) return;
    debug_enable(command);
}

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureWebApp.Migrations
{
    /// <inheritdoc />
    public partial class AddSecretNoteToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "SecretNote",
                table: "AspNetUsers",
                type: "varbinary(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SecretNote",
                table: "AspNetUsers");
        }
    }
}

-- AlterTable
ALTER TABLE "Order" ADD COLUMN     "buyerName" TEXT,
ADD COLUMN     "notes" TEXT,
ADD COLUMN     "paymentStatus" TEXT DEFAULT 'Paid';

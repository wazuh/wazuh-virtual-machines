# Installing the Wazuh AMI

There are two alternatives for deploying a Wazuh instance. You can launch the Wazuh All-In-One Deployment AMI directly from the AWS Marketplace or you can configure and deploy an instance using the AWS Management Console.

## Launching the Wazuh AMI from the AWS Marketplace

1. Go to [Wazuh All-In-One Deployment](https://aws.amazon.com/marketplace/pp/prodview-eju4flv5eqmgq?ref=hmpg_recommendations_widget) in the AWS Marketplace, then click **Continue to Subscribe**.
2. Review the information and accept the terms for the software. Click **Continue to Configuration** to confirm subscribing to our Server product.
3. Select a **Software Version** and the **Region** where the instance is going to be deployed. Then, click **Continue to Launch**.
4. Review your configuration, making sure that all settings are correct before launching the software. Adapt the default configuration values to your needs.
    1. **Instance Type**: When selecting the EC2 Instance Type, we recommend that you use an instance type `c5a.xlarge`.
    2. **Network Settings**: When selecting the **Security Group**, it must be one with the appropriate settings for your Wazuh instance to guarantee the correct operation. You can create a new security group by choosing **Create new based on seller** settings. This new group will have the appropriate settings by default.
5. Click **Launch** to start the instance.

Once your instance is successfully launched and a few minutes have elapsed, you can access the Wazuh dashboard.

## Deploy an instance using the AWS Management Console

1. Select **Launch instance** from your AWS Management Console dashboard.

2. Find **Wazuh All-In-One Deployment by Wazuh Inc.**, and click **Select** to subscribe.

3. Review the Server product characteristics, then click **Continue**. This allows subscribing to our Server product.

4. Select the instance type according to your needs, then click Next: Configure Instance Details. We recommend that you use an instance type `c5a.xlarge`.

5. Configure your instance as needed, then click Next: **Add Storage**.

6. Set the storage capacity of your instance under the **Size (GiB)** column, then click Next: **Add Tags**. We recommend 100 GiB GP3 or more.

7. Add as many tags as you need, then click Next: **Configure Security Group**.

8. Check that the ports and protocols are the ports and protocols for Wazuh. Check the security measures for your instance. This will establish the Security Group (SG). Then, click **Review and Launch**.

9. Review the instance configuration and click **Launch**.

10. Select one of three configuration alternatives available regarding the key pair settings: **Choose an existing key pair**, **Create a new key pair**, Proceed without a key pair. You need to choose an existing key pair or create a new one to access the instance with SSH.

11. Click **Launch instances** to complete the process and deploy your instance.

Once your instance is fully configured and ready after a few minutes since launch, you can access the Wazuh dashboard.
